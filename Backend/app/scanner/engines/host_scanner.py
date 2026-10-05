"""
QuantumShield — Container & Filesystem Inspection Engine (Track B, Stage 15)

High-performance, defensive, static inspection engine for:
  - Container image archives (Docker / OCI tar, tar.gz)
  - Extracted container image layouts
  - Authorized host and repository filesystems

Discovers:
  - Certificates (X.509 PEM, DER, bundles, chain reconstruction)
  - Private & Public Keys (RSA, EC, Ed25519, Ed448, encryption detection, fingerprints)
  - Keystores (PKCS#12, JKS, Trust Stores without password guessing)
  - Crypto configurations (SSH, Nginx, Apache, OpenSSL, Java security)
  - Environment variables (strictly redacted)
  - OS packages (dpkg, apk) & Language packages (pypi, npm, maven, go)
  - Crypto libraries and binaries (OpenSSL, BoringSSL, liboqs, libsodium)
  - Post-Quantum Cryptography (PQC) readiness & algorithms

CRITICAL INVARIANTS:
  - Strictly static: zero execution of binaries, entrypoints, or shell scripts.
  - Zero raw private key or credential retention.
  - Factual observation recording: risk scoring deferred to downstream engines.
"""

from __future__ import annotations

import os
import time
from typing import Any, List, Optional

from app.scanner.container.coordinator import InspectionCoordinator
from app.scanner.container.models import (
    ConfidenceLevel,
    CryptoObservation,
    InspectionTarget,
    ResourceLimits,
    TargetAuthorization,
    TargetType,
)
from app.scanner.models import (
    HostConfigFinding,
    InternalCertFinding,
    StageResult,
)
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


class HostScannerEngine(ScanStage):
    """Track B — Stage 15: Container & Filesystem Cryptographic Inspection Engine."""

    name = "host_scanner"
    order = 22
    timeout_seconds = 120
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields: list[str] = []
    writes_fields = [
        "host_config_findings",
        "internal_certificates",
        "crypto_observations",
        "container_findings",
        "package_findings",
    ]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        start_time = time.monotonic()

        # Resolve inspection paths and targets from scan options
        container_images = ctx.options.get("container_images") or []
        if isinstance(container_images, str):
            container_images = [container_images]

        filesystem_paths = ctx.options.get("filesystem_paths") or ctx.options.get("host_scan_paths") or ctx.options.get("source_code_paths") or []
        if isinstance(filesystem_paths, str):
            filesystem_paths = [filesystem_paths]

        explicit_targets = ctx.options.get("inspection_targets") or []

        # If none configured, check settings or environment
        if not container_images and not filesystem_paths and not explicit_targets:
            env_target = os.getenv("SCANNER_CONTAINER_TARGET") or os.getenv("SCANNER_SOURCE_CODE_PATH")
            if env_target:
                if env_target.endswith((".tar", ".tar.gz", ".tgz")):
                    container_images = [env_target]
                else:
                    filesystem_paths = [env_target]

        if not container_images and not filesystem_paths and not explicit_targets:
            logger.info("[%s] Container/Filesystem Engine: no paths or images configured — skipping", ctx.scan_id)
            return StageResult(
                status="skipped",
                data={
                    "host_config_findings": [],
                    "internal_certificates": [],
                    "crypto_observations": [],
                    "container_findings": [],
                    "package_findings": [],
                },
                error="No container_images or filesystem_paths provided in scan options",
            )

        coordinator = InspectionCoordinator(
            limits=ResourceLimits(),
            event_callback=lambda evt, payload: self._handle_coordinator_event(ctx, evt, payload),
        )

        all_observations: List[dict] = []
        all_internal_certs: List[dict] = []
        all_host_configs: List[dict] = []
        all_container_findings: List[dict] = []
        all_package_findings: List[dict] = []

        targets = self._build_inspection_targets(container_images, filesystem_paths, explicit_targets)

        for target in targets:
            logger.info(
                "[%s] Container/Filesystem Engine: Inspecting target %s (Type: %s, URI: %s)",
                ctx.scan_id, target.target_id, target.target_type.value, target.source_uri,
            )

            result = coordinator.inspect_target(target)

            # 1. Normalize Observations
            for obs in result.crypto_observations:
                obs_dict = obs.model_dump()
                all_observations.append(obs_dict)

                # Map certificates to InternalCertFinding for backward compatibility
                if obs.artifact_type == "certificate":
                    ev = obs.evidence
                    all_internal_certs.append(
                        InternalCertFinding(
                            file_path=obs.file_path,
                            file_extension=os.path.splitext(obs.file_path)[1].lower(),
                            subject_cn=ev.get("subject_cn") or obs.algorithm,
                            issuer_cn=ev.get("issuer_cn"),
                            not_valid_before=ev.get("not_valid_before"),
                            not_valid_after=ev.get("not_valid_after"),
                            key_type=obs.algorithm,
                            key_size=obs.key_size,
                            sig_algorithm=obs.signature_algorithm,
                            sig_algorithm_oid=obs.signature_algorithm,
                            fingerprint_sha256=obs.fingerprint,
                            expired=ev.get("expired", False),
                            days_until_expiry=ev.get("days_until_expiry"),
                            serial=ev.get("serial_number"),
                        ).model_dump()
                    )

                # Map private keys to InternalCertFinding notation
                elif obs.artifact_type == "private_key":
                    ev = obs.evidence
                    all_internal_certs.append(
                        InternalCertFinding(
                            file_path=obs.file_path,
                            file_extension=os.path.splitext(obs.file_path)[1].lower(),
                            subject_cn=f"[Private Key: {obs.algorithm} {obs.key_size or ''}b]",
                            key_type=obs.algorithm,
                            key_size=obs.key_size,
                            fingerprint_sha256=obs.fingerprint,
                        ).model_dump()
                    )

                # Map keystores
                elif obs.artifact_type in ("keystore", "trust_store"):
                    ev = obs.evidence
                    all_internal_certs.append(
                        InternalCertFinding(
                            file_path=obs.file_path,
                            file_extension=os.path.splitext(obs.file_path)[1].lower(),
                            subject_cn=f"[{obs.algorithm} Store — {ev.get('status', 'Inspected')}]",
                            key_type=obs.algorithm,
                            fingerprint_sha256=obs.fingerprint,
                        ).model_dump()
                    )

                # Map configs to HostConfigFinding
                elif obs.artifact_type == "crypto_config":
                    ev = obs.evidence
                    all_host_configs.append(
                        HostConfigFinding(
                            config_file=obs.file_path,
                            daemon=ev.get("daemon", "config"),
                            setting_name=ev.get("setting_name", "crypto"),
                            setting_value=ev.get("setting_value", ""),
                            algorithms_extracted=ev.get("algorithms_extracted", []),
                            risk_level="info",
                        ).model_dump()
                    )

            # 2. Collect container metadata and packages
            if "image_metadata" in result.target_metadata:
                all_container_findings.append(result.target_metadata["image_metadata"])

            for pkg in result.packages_discovered:
                all_package_findings.append(pkg.model_dump())

        # Feed discovered crypto packages into ctx.sca_findings for downstream SCA graph enrichment
        for pkg_dict in all_package_findings:
            if pkg_dict.get("is_crypto_relevant"):
                ctx.sca_findings.append({
                    "package": {"name": pkg_dict.get("name"), "version": pkg_dict.get("version"), "ecosystem": pkg_dict.get("ecosystem")},
                    "manifest_file": pkg_dict.get("source_file"),
                    "crypto_relevance": f"Discovered in container/filesystem: {', '.join(pkg_dict.get('crypto_primitives', []))}",
                    "crypto_primitives": pkg_dict.get("crypto_primitives", []),
                    "pqc_support": pkg_dict.get("pqc_support", []),
                })

        duration = time.monotonic() - start_time
        logger.info(
            "[%s] Container/Filesystem Engine completed: %d observations, %d certs, %d configs, %d packages in %.2fs",
            ctx.scan_id, len(all_observations), len(all_internal_certs), len(all_host_configs), len(all_package_findings), duration,
        )

        return StageResult(
            status="completed",
            data={
                "host_config_findings": all_host_configs,
                "internal_certificates": all_internal_certs,
                "crypto_observations": all_observations,
                "container_findings": all_container_findings,
                "package_findings": all_package_findings,
            },
            duration_seconds=round(duration, 2),
        )

    def _build_inspection_targets(
        self,
        container_images: List[str],
        filesystem_paths: List[str],
        explicit_targets: List[dict],
    ) -> List[InspectionTarget]:
        """Convert input paths into strongly-typed InspectionTarget objects."""
        targets: List[InspectionTarget] = []

        # Container archives
        for img_path in container_images:
            if not os.path.exists(img_path):
                logger.warning("Container target path not found: %s", img_path)
                continue
            t_type = TargetType.CONTAINER_ARCHIVE if os.path.isfile(img_path) else TargetType.EXTRACTED_IMAGE
            targets.append(
                InspectionTarget(
                    target_id=f"container-{os.path.basename(img_path)}",
                    target_type=t_type,
                    source_uri=os.path.abspath(img_path),
                    scope_root=os.path.abspath(img_path),
                    authorization=TargetAuthorization(
                        is_authorized=True,
                        scope_root=os.path.abspath(img_path),
                    ),
                )
            )

        # Filesystems
        for fs_path in filesystem_paths:
            if not os.path.exists(fs_path):
                logger.warning("Filesystem target path not found: %s", fs_path)
                continue
            # If path ends with .tar, treat as archive
            if os.path.isfile(fs_path) and fs_path.endswith((".tar", ".tar.gz", ".tgz")):
                t_type = TargetType.CONTAINER_ARCHIVE
            elif os.path.isdir(fs_path):
                t_type = TargetType.FILESYSTEM
            else:
                t_type = TargetType.FILESYSTEM

            targets.append(
                InspectionTarget(
                    target_id=f"fs-{os.path.basename(fs_path) or 'root'}",
                    target_type=t_type,
                    source_uri=os.path.abspath(fs_path),
                    scope_root=os.path.abspath(fs_path),
                    authorization=TargetAuthorization(
                        is_authorized=True,
                        scope_root=os.path.abspath(fs_path),
                    ),
                )
            )

        # Explicit target specs
        for spec in explicit_targets:
            try:
                targets.append(InspectionTarget(**spec))
            except Exception as exc:
                logger.warning("Invalid explicit inspection target spec: %s (%s)", spec, exc)

        return targets

    def _handle_coordinator_event(self, ctx: ScanContext, event_name: str, payload: dict) -> None:
        """Forward coordinator events to WebSocket telemetry."""
        try:
            ctx.broadcast(f"container_{event_name}", {
                "scan_id": ctx.scan_id,
                "stage": "container_filesystem_inspection",
                **payload,
            })
        except Exception:
            pass


# Backward-compatible alias
ContainerFilesystemEngine = HostScannerEngine
