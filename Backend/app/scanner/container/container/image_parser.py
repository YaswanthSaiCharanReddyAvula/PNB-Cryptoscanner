"""
QuantumShield — Static Container Image Manifest & Config Parser

Inspects OCI and Docker-compatible image archives statically.
Extracts immutable image digests, metadata, environment variables, entrypoints,
labels, and ordered layer descriptors without container execution.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, List, Optional, Tuple

from app.scanner.container.models import (
    ConfidenceLevel,
    ContainerImageMetadata,
    ContainerLayer,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ImageParseError(Exception):
    pass


class ContainerImageParser:
    """Static parser for OCI and Docker image structures."""

    @classmethod
    def parse_extracted_image(cls, image_dir: str) -> ContainerImageMetadata:
        """
        Inspect an uncompressed/extracted image directory (Docker or OCI layout).
        """
        image_dir = os.path.abspath(image_dir)

        # Check for Docker manifest.json
        docker_manifest = os.path.join(image_dir, "manifest.json")
        if os.path.isfile(docker_manifest):
            return cls._parse_docker_format(image_dir, docker_manifest)

        # Check for OCI layout
        oci_layout = os.path.join(image_dir, "oci-layout")
        oci_index = os.path.join(image_dir, "index.json")
        if os.path.isfile(oci_layout) and os.path.isfile(oci_index):
            return cls._parse_oci_format(image_dir, oci_index)

        raise ImageParseError(f"Directory {image_dir} does not contain valid Docker or OCI image manifests")

    @classmethod
    def _parse_docker_format(cls, image_dir: str, manifest_path: str) -> ContainerImageMetadata:
        """Parse standard Docker save archive layout."""
        try:
            with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                manifest_data = json.load(f)
        except Exception as exc:
            raise ImageParseError(f"Failed to read Docker manifest.json: {exc}")

        if not isinstance(manifest_data, list) or not manifest_data:
            raise ImageParseError("Docker manifest.json must be a non-empty array")

        primary = manifest_data[0]
        config_rel = primary.get("Config", "")
        repo_tags = primary.get("RepoTags") or []
        layer_paths = primary.get("Layers") or []

        repository = None
        tag = None
        if repo_tags:
            first_tag = repo_tags[0]
            if ":" in first_tag:
                repository, tag = first_tag.rsplit(":", 1)
            else:
                repository = first_tag

        # Load Config JSON
        config_path = os.path.join(image_dir, config_rel)
        config_data = {}
        image_digest = ""

        if os.path.isfile(config_path):
            try:
                with open(config_path, "rb") as f:
                    raw_cfg = f.read()
                    config_data = json.loads(raw_cfg.decode("utf-8", errors="ignore"))
                    # Compute immutable digest from config file
                    image_digest = f"sha256:{hashlib.sha256(raw_cfg).hexdigest()}"
            except Exception as exc:
                logger.warning("Failed to parse image config %s: %s", config_path, exc)

        if not image_digest:
            # Fallback to config basename or hash of manifest
            with open(manifest_path, "rb") as f:
                image_digest = f"sha256:{hashlib.sha256(f.read()).hexdigest()}"

        cfg_section = config_data.get("config") or {}
        architecture = config_data.get("architecture")
        os_name = config_data.get("os")
        created_at = config_data.get("created")

        entrypoint = cfg_section.get("Entrypoint") or []
        cmd = cfg_section.get("Cmd") or []
        env_vars = cfg_section.get("Env") or []
        labels = cfg_section.get("Labels") or {}
        working_dir = cfg_section.get("WorkingDir")
        user = cfg_section.get("User")
        is_root = not user or user in ("0", "root", "0:0")

        # Ordered layer descriptors
        layers: List[ContainerLayer] = []
        diff_ids = (config_data.get("rootfs") or {}).get("diff_ids") or []

        for idx, layer_rel in enumerate(layer_paths):
            layer_abs = os.path.join(image_dir, layer_rel)
            digest = diff_ids[idx] if idx < len(diff_ids) else f"layer-{idx}"
            size = os.path.getsize(layer_abs) if os.path.isfile(layer_abs) else 0

            layers.append(
                ContainerLayer(
                    layer_index=idx,
                    layer_digest=digest,
                    layer_tar_path=layer_abs,
                    size_bytes=size,
                )
            )

        return ContainerImageMetadata(
            image_digest=image_digest,
            repository=repository,
            tag=tag,
            identity_confidence=ConfidenceLevel.HIGH,
            architecture=architecture,
            os=os_name,
            created_at=created_at,
            config=config_data,
            entrypoint=entrypoint if isinstance(entrypoint, list) else [str(entrypoint)],
            cmd=cmd if isinstance(cmd, list) else [str(cmd)],
            env_vars=env_vars if isinstance(env_vars, list) else [],
            labels=labels if isinstance(labels, dict) else {},
            working_dir=working_dir,
            user=user,
            is_root_user=is_root,
            layers=layers,
        )

    @classmethod
    def _parse_oci_format(cls, image_dir: str, index_path: str) -> ContainerImageMetadata:
        """Parse standard OCI image layout."""
        try:
            with open(index_path, "r", encoding="utf-8", errors="ignore") as f:
                index_data = json.load(f)
        except Exception as exc:
            raise ImageParseError(f"Failed to read OCI index.json: {exc}")

        manifests = index_data.get("manifests") or []
        if not manifests:
            raise ImageParseError("OCI index.json contains no manifests")

        first_manifest = manifests[0]
        manifest_digest = first_manifest.get("digest", "")
        # Locate blob
        blob_hash = manifest_digest.replace("sha256:", "")
        manifest_blob_path = os.path.join(image_dir, "blobs", "sha256", blob_hash)

        config_data = {}
        image_digest = manifest_digest
        layer_blobs: List[str] = []

        if os.path.isfile(manifest_blob_path):
            try:
                with open(manifest_blob_path, "r", encoding="utf-8", errors="ignore") as f:
                    manifest_content = json.load(f)
                config_desc = manifest_content.get("config") or {}
                cfg_digest = config_desc.get("digest", "").replace("sha256:", "")
                if cfg_digest:
                    cfg_blob_path = os.path.join(image_dir, "blobs", "sha256", cfg_digest)
                    if os.path.isfile(cfg_blob_path):
                        with open(cfg_blob_path, "r", encoding="utf-8", errors="ignore") as cf:
                            config_data = json.load(cf)

                for l in manifest_content.get("layers") or []:
                    layer_digest = l.get("digest", "")
                    l_hash = layer_digest.replace("sha256:", "")
                    l_path = os.path.join(image_dir, "blobs", "sha256", l_hash)
                    layer_blobs.append((layer_digest, l_path))
            except Exception as exc:
                logger.warning("Error reading OCI manifest blob %s: %s", manifest_blob_path, exc)

        cfg_section = config_data.get("config") or {}
        entrypoint = cfg_section.get("Entrypoint") or []
        cmd = cfg_section.get("Cmd") or []
        env_vars = cfg_section.get("Env") or []
        labels = cfg_section.get("Labels") or {}
        user = cfg_section.get("User")

        layers: List[ContainerLayer] = []
        for idx, (digest, path) in enumerate(layer_blobs):
            size = os.path.getsize(path) if os.path.isfile(path) else 0
            layers.append(
                ContainerLayer(
                    layer_index=idx,
                    layer_digest=digest,
                    layer_tar_path=path,
                    size_bytes=size,
                )
            )

        return ContainerImageMetadata(
            image_digest=image_digest or f"sha256:{blob_hash}",
            repository=first_manifest.get("annotations", {}).get("org.opencontainers.image.ref.name"),
            identity_confidence=ConfidenceLevel.HIGH,
            architecture=config_data.get("architecture"),
            os=config_data.get("os"),
            created_at=config_data.get("created"),
            config=config_data,
            entrypoint=entrypoint if isinstance(entrypoint, list) else [str(entrypoint)],
            cmd=cmd if isinstance(cmd, list) else [str(cmd)],
            env_vars=env_vars if isinstance(env_vars, list) else [],
            labels=labels if isinstance(labels, dict) else {},
            user=user,
            is_root_user=not user or user in ("0", "root", "0:0"),
            layers=layers,
        )
