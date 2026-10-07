"""
QuantumShield — Convergence SAST Adapter

Transforms SAST findings into canonical models.
"""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter
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
            finding_uuid = str(uuid.uuid4())
            repo = finding.repository or "local_repo"
            
            # 1. Create Evidence for the SAST finding
            # Hash the evidence to avoid storing raw secrets in the value field if it's a secret
            is_secret = finding.finding_type == "HARDCODED_SECRET"
            value_str = None
            value_hash = None
            redaction_status = ObservationStatus.UNKNOWN
            
            if is_secret:
                value_hash = hashlib.sha256(finding.evidence.encode('utf-8')).hexdigest()
                redaction_status = ObservationStatus.REDACTED
            else:
                value_str = finding.evidence
                
            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type=finding.finding_type or "sast_finding",
                target=repo,
                location=f"{finding.file_path}:{finding.line_number}",
                observed_at=now,
                confidence=finding.confidence,
                value=value_str,
                value_hash=value_hash,
                redaction_status=redaction_status
            )
            evidence.append(ev)

            # 2. Represent the Cryptographic Algorithm (if any) as an Asset
            algo_asset_id = None
            if finding.algorithm:
                algo_asset = CanonicalAsset(
                    scan_id=ctx.scan_id,
                    asset_type=AssetType.ALGORITHM,
                    name=finding.algorithm,
                    properties={
                        "primitive": finding.operation,
                        "mode": finding.mode,
                        "padding": finding.padding,
                        "key_size": finding.key_size,
                        "curve": finding.curve
                    },
                    observed_at=now,
                    sources=[self.engine_name],
                    evidence_refs=[ev.evidence_id]
                )
                assets.append(algo_asset)
                algo_asset_id = algo_asset.asset_id

            # 3. Represent the Library/Module (if any) as an Asset
            lib_asset_id = None
            if finding.module:
                lib_asset = CanonicalAsset(
                    scan_id=ctx.scan_id,
                    asset_type=AssetType.LIBRARY,
                    name=finding.module,
                    observed_at=now,
                    sources=[self.engine_name],
                    evidence_refs=[ev.evidence_id]
                )
                assets.append(lib_asset)
                lib_asset_id = lib_asset.asset_id
                
                if algo_asset_id:
                    # Link algorithm to the library that implements it
                    algo_asset.relationships.append(
                        Relationship(type="implemented_by", target_id=lib_asset_id)
                    )

            # 4. Create the Canonical Finding
            severity_str = (finding.severity or "info").upper()
            severity = RiskLevel.UNKNOWN
            if severity_str in [r.value for r in RiskLevel]:
                severity = RiskLevel(severity_str)
            elif severity_str == "INFO":
                severity = RiskLevel.SAFE
                
            cf = CanonicalFinding(
                finding_id=finding_uuid,
                scan_id=ctx.scan_id,
                finding_type=finding.finding_type or "sast_observation",
                title=f"SAST Crypto Observation in {finding.file_path}",
                description=f"Observed {finding.operation or finding.api or 'usage'} involving {finding.algorithm or finding.module or 'crypto material'}",
                severity=severity,
                confidence=finding.confidence,
                status=ObservationStatus.OBSERVED,
                source=[self.engine_name],
                evidence_refs=[ev.evidence_id],
                details={
                    "repository": repo,
                    "commit": finding.commit,
                    "branch": finding.branch,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "function": finding.function,
                    "language": finding.language,
                    "secret_type": finding.secret_type,
                    "api": finding.api
                }
            )
            
            if algo_asset_id:
                cf.asset_refs.append(algo_asset_id)
            if lib_asset_id:
                cf.asset_refs.append(lib_asset_id)
                
            findings.append(cf)

        return assets, findings, evidence
