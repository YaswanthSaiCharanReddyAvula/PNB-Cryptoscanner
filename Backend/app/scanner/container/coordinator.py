"""
QuantumShield — Inspection Coordinator

Orchestrates container image inspection, safe layer reconstruction, filesystem traversal,
artifact classification, and evidence normalization.
Provides a unified interface for all inspection targets (containers, archives, filesystems).
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from app.scanner.container.binary.binary_inspector import BinaryInspector
from app.scanner.container.container.archive import SafeArchiveExtractor
from app.scanner.container.container.image_parser import ContainerImageParser
from app.scanner.container.container.layer_reconstructor import LayerReconstructor
from app.scanner.container.crypto.cert_parser import CertificateParser
from app.scanner.container.crypto.config_parser import ConfigParser
from app.scanner.container.crypto.key_parser import KeyParser
from app.scanner.container.crypto.keystore_parser import KeystoreParser
from app.scanner.container.crypto.pqc_detector import PQCDetector
from app.scanner.container.filesystem.traversal import SafeFilesystemWalker
from app.scanner.container.models import (
    ArtifactType,
    ConfidenceLevel,
    ContainerImageMetadata,
    CryptoObservation,
    FileArtifact,
    InspectionResult,
    InspectionTarget,
    PackageObservation,
    PQCClassification,
    ResourceLimits,
    TargetType,
)
from app.scanner.container.packages.crypto_libraries import CryptoLibraryMatcher
from app.scanner.container.packages.language_packages import LanguagePackageParser
from app.scanner.container.packages.os_packages import OSPackageParser
from app.utils.logger import get_logger

logger = get_logger(__name__)


class InspectionCoordinator:
    """Master coordinator for static container and filesystem inspection."""

    def __init__(
        self,
        limits: ResourceLimits | None = None,
        scratch_base_dir: Optional[str] = None,
        event_callback: Optional[Callable[[str, dict], Any]] = None,
    ):
        self.limits = limits or ResourceLimits()
        self.scratch_base_dir = scratch_base_dir or tempfile.gettempdir()
        self.event_callback = event_callback or (lambda evt, data: None)

    def inspect_target(self, target: InspectionTarget) -> InspectionResult:
        """Execute full static inspection on an InspectionTarget."""
        start_time = time.monotonic()
        self._emit_event("inspection_started", {"target_id": target.target_id, "type": target.target_type.value})

        result = InspectionResult(
            target_metadata={
                "target_id": target.target_id,
                "target_type": target.target_type.value,
                "source_uri": target.source_uri,
                "scope_root": target.scope_root,
            }
        )

        try:
            if target.target_type in (TargetType.CONTAINER_ARCHIVE, TargetType.CONTAINER_IMAGE):
                self._inspect_container_archive(target, result)
            elif target.target_type == TargetType.EXTRACTED_IMAGE:
                self._inspect_extracted_container_image(target, target.source_uri, result)
            elif target.target_type in (TargetType.FILESYSTEM, TargetType.REPOSITORY):
                self._inspect_filesystem(target, target.source_uri, result)
            else:
                result.parser_errors.append({"error": f"Unsupported target type: {target.target_type}"})

        except Exception as exc:
            logger.exception("InspectionCoordinator failed for target %s", target.target_id)
            result.parser_errors.append({"error": str(exc)})

        duration = time.monotonic() - start_time
        result.scan_metadata = {
            "duration_seconds": round(duration, 2),
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "completed" if not result.parser_errors else "completed_with_errors",
        }
        result.coverage = {
            "files_inspected": result.files_inspected,
            "files_skipped": result.files_skipped,
            "crypto_observations_count": len(result.crypto_observations),
            "packages_count": len(result.packages_discovered),
        }

        self._emit_event("inspection_completed", {"target_id": target.target_id, "summary": result.coverage})
        return result

    def _inspect_container_archive(self, target: InspectionTarget, result: InspectionResult) -> None:
        """Extract container tar archive safely into scratch sandbox and inspect."""
        archive_path = target.source_uri
        if not os.path.isfile(archive_path):
            result.parser_errors.append({"error": f"Container archive file not found: {archive_path}"})
            return

        with tempfile.TemporaryDirectory(prefix="container_arch_", dir=self.scratch_base_dir) as scratch_dir:
            extractor = SafeArchiveExtractor(limits=self.limits)
            try:
                extractor.safe_extract_tar(archive_path, scratch_dir)
            except Exception as exc:
                result.parser_errors.append({"error": f"Archive extraction failed: {exc}"})
                return

            result.resource_limit_events.extend(extractor.events)
            self._inspect_extracted_container_image(target, scratch_dir, result)

    def _inspect_extracted_container_image(
        self, target: InspectionTarget, image_dir: str, result: InspectionResult
    ) -> None:
        """Inspect uncompressed OCI or Docker image layout."""
        try:
            image_meta = ContainerImageParser.parse_extracted_image(image_dir)
            result.target_metadata["image_metadata"] = image_meta.model_dump()
            self._emit_event("image_metadata_discovered", {"digest": image_meta.image_digest, "layers": len(image_meta.layers)})
        except Exception as exc:
            result.parser_errors.append({"error": f"Image manifest parse error: {exc}"})
            # Still attempt raw filesystem scan of the directory
            self._inspect_filesystem(target, image_dir, result)
            return

        # Reconstruct layers into merged filesystem view
        with tempfile.TemporaryDirectory(prefix="container_merged_", dir=self.scratch_base_dir) as merged_dir:
            reconstructor = LayerReconstructor(limits=self.limits)
            reconstruct_result = reconstructor.reconstruct_layers(image_meta.layers, merged_dir)
            result.resource_limit_events.extend(reconstruct_result.events)

            # Inspect environment variables statically
            env_obs = ConfigParser.inspect_env_variables(image_meta.env_vars, target.target_id)
            for obs in env_obs:
                obs.image_digest = image_meta.image_digest
                result.crypto_observations.append(obs)

            # Traverse merged filesystem view
            self._inspect_filesystem(
                target=target,
                scan_root=merged_dir,
                result=result,
                image_meta=image_meta,
                provenance_map=reconstruct_result.provenance,
            )

    def _inspect_filesystem(
        self,
        target: InspectionTarget,
        scan_root: str,
        result: InspectionResult,
        image_meta: Optional[ContainerImageMetadata] = None,
        provenance_map: Optional[dict] = None,
    ) -> None:
        """Traverse filesystem and run artifact classification and crypto parsers."""
        walker = SafeFilesystemWalker(
            authorized_root=scan_root,
            limits=self.limits,
        )

        artifacts = walker.walk(sub_scope="")
        result.files_inspected += walker.files_inspected
        result.files_skipped += walker.files_skipped
        result.resource_limit_events.extend(walker.events)
        result.parser_errors.extend(walker.errors)

        raw_certs: List[CryptoObservation] = []
        raw_keys: List[CryptoObservation] = []

        # 1. First pass: OS package databases in scan root
        os_pkgs = OSPackageParser.discover_os_packages(scan_root)
        for pkg in os_pkgs:
            # Check crypto registry match
            crypto_obs = CryptoLibraryMatcher.match_package(pkg, target.target_id)
            if crypto_obs:
                if image_meta:
                    crypto_obs.image_digest = image_meta.image_digest
                result.crypto_observations.append(crypto_obs)
                result.libraries.append(crypto_obs.model_dump())

            # Check PQC package match
            pqc_obs = PQCDetector.evaluate_package(pkg, target.target_id)
            if pqc_obs:
                if image_meta:
                    pqc_obs.image_digest = image_meta.image_digest
                result.crypto_observations.append(pqc_obs)
                result.pqc_observations.append(pqc_obs.model_dump())

            result.packages_discovered.append(pkg)

        # 2. Second pass: File by file static inspection
        for art in artifacts:
            rel = art.relative_path
            fp_info = provenance_map.get(rel) if provenance_map else None

            # Attach layer provenance if present
            if fp_info:
                art.layer_index = fp_info.layer_introduced
                art.layer_digest = fp_info.layer_introduced_digest

            # Certificates
            if art.file_type == "certificate" or art.relative_path.endswith((".pem", ".crt", ".cer", ".der")):
                certs = CertificateParser.parse_file(art.file_path, target.target_id)
                for c in certs:
                    self._enrich_observation(c, image_meta, fp_info)
                    raw_certs.append(c)
                    result.crypto_observations.append(c)
                    result.certificates.append(c.model_dump())
                    result.artifacts_discovered += 1

            # Private & Public Keys
            elif art.file_type in ("private_key_candidate", "public_key") or art.relative_path.endswith((".key", ".pub")):
                keys = KeyParser.parse_file(art.file_path, target.target_id)
                for k in keys:
                    self._enrich_observation(k, image_meta, fp_info)
                    raw_keys.append(k)
                    result.crypto_observations.append(k)
                    result.keys.append(k.model_dump())
                    result.artifacts_discovered += 1

            # Keystores & Trust Stores
            elif art.file_type == "keystore" or art.relative_path.endswith((".jks", ".p12", ".pfx", "ca-certificates.crt")):
                stores = KeystoreParser.parse_file(art.file_path, target.target_id)
                for s in stores:
                    self._enrich_observation(s, image_meta, fp_info)
                    result.crypto_observations.append(s)
                    result.artifacts_discovered += 1

            # Configs
            elif art.file_type == "crypto_config":
                configs = ConfigParser.parse_file(art.file_path, target.target_id)
                for cfg in configs:
                    self._enrich_observation(cfg, image_meta, fp_info)
                    result.crypto_observations.append(cfg)
                    result.configs.append(cfg.model_dump())
                    result.artifacts_discovered += 1

                # Check for PQC keywords in config
                try:
                    with open(art.file_path, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read(32768)
                    pqc_cfg = PQCDetector.inspect_text_content(text, art.file_path, target.target_id)
                    for p in pqc_cfg:
                        self._enrich_observation(p, image_meta, fp_info)
                        result.crypto_observations.append(p)
                        result.pqc_observations.append(p.model_dump())
                except Exception:
                    pass

            # Package manifests (Python, npm, Go, Java)
            elif art.file_type == "package_metadata":
                pkgs = LanguagePackageParser.parse_manifest(art.file_path)
                for pkg in pkgs:
                    # Enrich with crypto registry
                    crypto_obs = CryptoLibraryMatcher.match_package(pkg, target.target_id)
                    if crypto_obs:
                        self._enrich_observation(crypto_obs, image_meta, fp_info)
                        result.crypto_observations.append(crypto_obs)
                        result.libraries.append(crypto_obs.model_dump())

                    pqc_obs = PQCDetector.evaluate_package(pkg, target.target_id)
                    if pqc_obs:
                        self._enrich_observation(pqc_obs, image_meta, fp_info)
                        result.crypto_observations.append(pqc_obs)
                        result.pqc_observations.append(pqc_obs.model_dump())

                    result.packages_discovered.append(pkg)

            # Binaries & Shared Libraries
            elif art.file_type in ("binary", "shared_library"):
                bin_obs = BinaryInspector.inspect_binary(art.file_path, target.target_id)
                for b in bin_obs:
                    self._enrich_observation(b, image_meta, fp_info)
                    result.crypto_observations.append(b)
                    result.libraries.append(b.model_dump())
                    result.artifacts_discovered += 1

        # 3. Third pass: Certificate Chain Reconstruction & Key-Cert Correlation
        if raw_certs:
            CertificateParser.reconstruct_chains(raw_certs)

        if raw_keys and raw_certs:
            correlations = KeyParser.correlate_keys_and_certs(raw_keys, raw_certs)
            for corr in correlations:
                result.target_metadata.setdefault("key_cert_correlations", []).append(corr)

    def _enrich_observation(
        self,
        obs: CryptoObservation,
        image_meta: Optional[ContainerImageMetadata],
        fp_info: Optional[Any],
    ) -> None:
        """Attach container metadata and historical layer provenance."""
        if image_meta:
            obs.image_digest = image_meta.image_digest
        if fp_info:
            obs.layer_index = fp_info.layer_introduced
            obs.layer_digest = fp_info.layer_introduced_digest
            obs.final_image_presence = fp_info.final_image_presence
            obs.historical_layer_presence = fp_info.historical_layer_presence
            if not fp_info.final_image_presence:
                obs.evidence["layer_deleted"] = fp_info.layer_deleted
                obs.evidence["layer_deleted_digest"] = fp_info.layer_deleted_digest

    def _emit_event(self, event_name: str, payload: dict) -> None:
        """Emit telemetry event via callback."""
        try:
            self.event_callback(event_name, payload)
        except Exception:
            pass
