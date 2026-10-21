"""
QuantumShield — Convergence SAST Adapter

Transforms SAST findings into canonical models.
"""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter, extract_field
from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
    Identifier,
    Location,
    Relationship,
)
from app.scanner.convergence.enums import AssetType, ObservationStatus, RiskLevel
from app.scanner.convergence.normalizers import normalize_technology, normalize_version
from app.scanner.models import SASTFinding
from app.scanner.pipeline import ScanContext
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SASTAdapter(EngineAdapter):
    @property
    def engine_name(self) -> str:
        return "sast_crypto"

    @property
    def engine_stage(self) -> str:
        return "source/sast"

    def process(self, ctx: ScanContext) -> Tuple[List[CanonicalAsset], List[CanonicalFinding], List[CanonicalEvidence]]:
        assets: List[CanonicalAsset] = []
        findings: List[CanonicalFinding] = []
        evidence: List[CanonicalEvidence] = []
        
        now = datetime.now(timezone.utc)

        for finding in getattr(ctx, "sast_findings", []):
            if not isinstance(finding, (dict, SASTFinding)) and not hasattr(finding, "file_path"):
                msg = f"Skipping malformed SAST finding record: invalid type {type(finding).__name__}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            file_path = extract_field(finding, "file_path", "")
            finding_type = extract_field(finding, "finding_type", "sast_finding")
            repo = extract_field(finding, "repository") or "local_repo"
            evidence_val = extract_field(finding, "evidence", "")
            line_number = extract_field(finding, "line_number", 0)
            conf_raw = extract_field(finding, "confidence", 1.0)
            try:
                confidence = float(conf_raw) if conf_raw is not None else 1.0
            except (ValueError, TypeError):
                confidence = 1.0

            # 1. Create Evidence for the SAST finding
            # Hash the evidence to avoid storing raw secrets in the value field if it's a secret
            is_secret = finding_type == "HARDCODED_SECRET"
            value_str = None
            value_hash = None
            redaction_status = ObservationStatus.UNKNOWN
            
            if is_secret:
                ev_str = str(evidence_val or "")
                value_hash = hashlib.sha256(ev_str.encode('utf-8')).hexdigest()
                redaction_status = ObservationStatus.REDACTED
            else:
                value_str = str(evidence_val) if evidence_val is not None else None
                
            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type=str(finding_type or "sast_finding"),
                target=str(repo),
                location=f"{file_path}:{line_number}" if file_path else None,
                observed_at=now,
                confidence=confidence,
                value=value_str,
                value_hash=value_hash,
                redaction_status=redaction_status,
            )
            evidence.append(ev)

            # 2. Represent the Cryptographic Algorithm (if any) as an Asset
            algo_asset_id = None
            algorithm = extract_field(finding, "algorithm")
            operation = extract_field(finding, "operation")
            mode = extract_field(finding, "mode")
            padding = extract_field(finding, "padding")
            key_size = extract_field(finding, "key_size")
            curve = extract_field(finding, "curve")
            module = extract_field(finding, "module")

            if algorithm and isinstance(algorithm, str) and algorithm.strip():
                algo_asset = CanonicalAsset(
                    scan_id=ctx.scan_id,
                    asset_type=AssetType.ALGORITHM,
                    name=algorithm.strip(),
                    properties={
                        "primitive": operation,
                        "mode": mode,
                        "padding": padding,
                        "key_size": key_size,
                        "curve": curve,
                    },
                    observed_at=now,
                    sources=[self.engine_name],
                    evidence_refs=[ev.evidence_id],
                )
                assets.append(algo_asset)
                algo_asset_id = algo_asset.asset_id

            # 3. Represent the Library/Module (if any) as an Asset
            lib_asset_id = None
            if module and isinstance(module, str) and module.strip():
                lib_asset = CanonicalAsset(
                    scan_id=ctx.scan_id,
                    asset_type=AssetType.LIBRARY,
                    name=module.strip(),
                    observed_at=now,
                    sources=[self.engine_name],
                    evidence_refs=[ev.evidence_id],
                )
                assets.append(lib_asset)
                lib_asset_id = lib_asset.asset_id
                
                if algo_asset_id:
                    algo_asset.relationships.append(
                        Relationship(type="implemented_by", target_id=lib_asset_id)
                    )

            # 4. Create the Canonical Finding
            raw_severity = extract_field(finding, "severity", "info")
            severity_str = str(raw_severity or "info").upper()
            if severity_str in [r.value for r in RiskLevel]:
                severity = RiskLevel(severity_str)
            elif severity_str in ("INFO", "NONE"):
                severity = RiskLevel.SAFE
            else:
                severity = RiskLevel.UNKNOWN
                
            cf = CanonicalFinding(
                finding_id=str(uuid.uuid4()),
                scan_id=ctx.scan_id,
                finding_type=str(finding_type or "sast_observation"),
                title=f"SAST Crypto Observation in {file_path or repo}",
                description=f"Observed {operation or extract_field(finding, 'api') or 'usage'} involving {algorithm or module or 'crypto material'}",
                severity=severity,
                confidence=confidence,
                status=ObservationStatus.OBSERVED,
                source=[self.engine_name],
                evidence_refs=[ev.evidence_id],
                details={
                    "repository": repo,
                    "commit": extract_field(finding, "commit"),
                    "branch": extract_field(finding, "branch"),
                    "file_path": file_path,
                    "line_number": line_number,
                    "function": extract_field(finding, "function"),
                    "language": extract_field(finding, "language"),
                    "secret_type": extract_field(finding, "secret_type"),
                    "api": extract_field(finding, "api"),
                },
            )
            
            if algo_asset_id:
                cf.asset_refs.append(algo_asset_id)
            if lib_asset_id:
                cf.asset_refs.append(lib_asset_id)
                
            findings.append(cf)

        return assets, findings, evidence
