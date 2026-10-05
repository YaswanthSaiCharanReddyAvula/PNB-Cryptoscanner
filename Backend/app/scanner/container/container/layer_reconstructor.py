"""
QuantumShield — Layer Reconstruction & Whiteout Resolution Engine

Applies OCI/Docker layer deltas in sequential order to produce a merged filesystem view.
Accurately interprets:
  - Standard whiteout (.wh.<filename>) -> file deletion from earlier layers
  - Opaque directory whiteout (.wh..wh..opq) -> masks all earlier layer files in directory
Tracks layer provenance (layer_introduced, layer_modified, layer_deleted, final_image_presence).
"""

from __future__ import annotations

import os
import shutil
import tempfile
from typing import Dict, List, Optional, Tuple

from app.scanner.container.container.archive import SafeArchiveExtractor
from app.scanner.container.models import ContainerLayer, ResourceLimits
from app.utils.logger import get_logger

logger = get_logger(__name__)

OPAQUE_WHITEOUT = ".wh..wh..opq"
WHITEOUT_PREFIX = ".wh."


class FileProvenance:
    """Historical tracking of a file across container layers."""

    def __init__(self, relative_path: str, introduced_layer: int, introduced_digest: str):
        self.relative_path = relative_path
        self.layer_introduced = introduced_layer
        self.layer_introduced_digest = introduced_digest
        self.layer_modified: Optional[int] = None
        self.layer_deleted: Optional[int] = None
        self.layer_deleted_digest: Optional[str] = None
        self.final_image_presence: bool = True
        self.historical_layer_presence: bool = True


class LayerReconstructionResult:
    """Outcome of layer reconstruction."""

    def __init__(self, merged_root: str):
        self.merged_root = merged_root
        self.provenance: Dict[str, FileProvenance] = {}
        self.events: List[str] = []


class LayerReconstructor:
    """Sequential layer delta merger with strict whiteout compliance."""

    def __init__(self, limits: ResourceLimits | None = None):
        self.limits = limits or ResourceLimits()
        self.extractor = SafeArchiveExtractor(limits=self.limits)

    def reconstruct_layers(
        self,
        layers: List[ContainerLayer],
        target_merged_dir: str,
    ) -> LayerReconstructionResult:
        """
        Extract and apply layers sequentially into target_merged_dir.
        Returns LayerReconstructionResult containing final merged root and provenance map.
        """
        dest_root = os.path.abspath(target_merged_dir)
        os.makedirs(dest_root, exist_ok=True)
        result = LayerReconstructionResult(merged_root=dest_root)

        for layer in layers:
            tar_path = layer.layer_tar_path
            if not tar_path or not os.path.isfile(tar_path):
                logger.warning("Layer tarball not found: %s", tar_path)
                continue

            # Extract layer into an isolated temporary scratch folder first
            with tempfile.TemporaryDirectory(prefix=f"layer_{layer.layer_index}_") as layer_temp_dir:
                try:
                    self.extractor.safe_extract_tar(tar_path, layer_temp_dir)
                except Exception as exc:
                    result.events.append(f"LAYER_EXTRACT_ERROR: Layer {layer.layer_index}: {exc}")
                    logger.warning("Failed extracting layer %d: %s", layer.layer_index, exc)
                    continue

                # Scan layer for whiteouts and files
                self._apply_layer_diff(layer_temp_dir, dest_root, layer, result)

        return result

    def _apply_layer_diff(
        self,
        layer_dir: str,
        dest_root: str,
        layer: ContainerLayer,
        result: LayerReconstructionResult,
    ) -> None:
        """Process layer files, resolving whiteouts and updating merged view."""
        for root, dirs, files in os.walk(layer_dir, topdown=True):
            rel_dir = os.path.relpath(root, layer_dir).replace("\\", "/")
            if rel_dir == ".":
                rel_dir = ""

            dest_dir = os.path.join(dest_root, rel_dir) if rel_dir else dest_root
            os.makedirs(dest_dir, exist_ok=True)

            # Check for opaque whiteout (.wh..wh..opq) in current directory
            if OPAQUE_WHITEOUT in files:
                layer.opaque_whiteout_dirs.append(rel_dir)
                result.events.append(f"OPAQUE_WHITEOUT: Masking directory /{rel_dir} in layer {layer.layer_index}")
                # Remove all existing files in dest_dir that were introduced in lower layers
                if os.path.isdir(dest_dir):
                    for existing_item in os.listdir(dest_dir):
                        item_rel = f"{rel_dir}/{existing_item}".lstrip("/")
                        full_existing_path = os.path.join(dest_dir, existing_item)
                        self._mark_deleted(item_rel, layer, result)
                        try:
                            if os.path.isdir(full_existing_path) and not os.path.islink(full_existing_path):
                                shutil.rmtree(full_existing_path, ignore_errors=True)
                            else:
                                os.remove(full_existing_path)
                        except OSError:
                            pass

            # Process individual files & standard whiteouts (.wh.<filename>)
            for filename in files:
                if filename == OPAQUE_WHITEOUT:
                    continue

                if filename.startswith(WHITEOUT_PREFIX):
                    # Standard deletion marker
                    deleted_target_name = filename[len(WHITEOUT_PREFIX):]
                    deleted_rel = f"{rel_dir}/{deleted_target_name}".lstrip("/")
                    layer.whiteout_files.append(deleted_rel)
                    layer.deleted_files.append(deleted_rel)

                    dest_target_file = os.path.join(dest_dir, deleted_target_name)
                    if os.path.exists(dest_target_file) or os.path.islink(dest_target_file):
                        try:
                            if os.path.isdir(dest_target_file) and not os.path.islink(dest_target_file):
                                shutil.rmtree(dest_target_file, ignore_errors=True)
                            else:
                                os.remove(dest_target_file)
                        except OSError:
                            pass

                    self._mark_deleted(deleted_rel, layer, result)
                    result.events.append(f"WHITEOUT_APPLIED: Deleted /{deleted_rel} in layer {layer.layer_index}")
                else:
                    # Regular file addition / modification
                    source_file = os.path.join(root, filename)
                    dest_file = os.path.join(dest_dir, filename)
                    file_rel = f"{rel_dir}/{filename}".lstrip("/")

                    if os.path.exists(dest_file) or os.path.islink(dest_file):
                        # File was modified
                        layer.modified_files.append(file_rel)
                        if file_rel in result.provenance:
                            prov = result.provenance[file_rel]
                            prov.layer_modified = layer.layer_index
                            prov.final_image_presence = True
                    else:
                        # File introduced
                        layer.introduced_files.append(file_rel)
                        result.provenance[file_rel] = FileProvenance(
                            relative_path=file_rel,
                            introduced_layer=layer.layer_index,
                            introduced_digest=layer.layer_digest,
                        )

                    # Copy to merged destination (without executing)
                    try:
                        if os.path.islink(source_file):
                            link_target = os.readlink(source_file)
                            if os.path.exists(dest_file) or os.path.islink(dest_file):
                                os.remove(dest_file)
                            os.symlink(link_target, dest_file)
                        else:
                            shutil.copy2(source_file, dest_file)
                    except Exception as exc:
                        logger.debug("Error copying file %s to merged view: %s", source_file, exc)

    @staticmethod
    def _mark_deleted(relative_path: str, layer: ContainerLayer, result: LayerReconstructionResult) -> None:
        """Mark a file as deleted in historical provenance."""
        if relative_path in result.provenance:
            prov = result.provenance[relative_path]
            prov.final_image_presence = False
            prov.layer_deleted = layer.layer_index
            prov.layer_deleted_digest = layer.layer_digest
        else:
            # File introduced in a lower layer that wasn't previously tracked
            prov = FileProvenance(relative_path, introduced_layer=0, introduced_digest="unknown")
            prov.final_image_presence = False
            prov.layer_deleted = layer.layer_index
            prov.layer_deleted_digest = layer.layer_digest
            result.provenance[relative_path] = prov
