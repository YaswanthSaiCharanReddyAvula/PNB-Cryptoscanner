"""
QuantumShield — Convergence SCA Adapter

Transforms SCA package findings and vulnerabilities into canonical models.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter, extract_field
from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
    CanonicalPackage,
    Identifier,
    Location,
)
from app.scanner.convergence.enums import AssetType, ObservationStatus, RiskLevel
from app.scanner.pipeline import ScanContext
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SCAAdapter(EngineAdapter):
    @property
    def engine_name(self) -> str:
        return "sca_engine"

    @property
    def engine_stage(self) -> str:
        return "source/sca"

    def process(self, ctx: ScanContext) -> Tuple[List[CanonicalAsset], List[CanonicalFinding], List[CanonicalEvidence]]:
        assets: List[CanonicalAsset] = []
        findings: List[CanonicalFinding] = []
        evidence: List[CanonicalEvidence] = []
        
        now = datetime.now(timezone.utc)

        # Handle package_findings (discovered dependencies)
        for pkg_data in getattr(ctx, "package_findings", []):
            if not isinstance(pkg_data, dict) and not hasattr(pkg_data, "name") and not hasattr(pkg_data, "package"):
                msg = f"Skipping malformed package finding record: invalid type {type(pkg_data).__name__}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            pkg_identity = extract_field(pkg_data, "package", pkg_data)
            name = extract_field(pkg_identity, "name") or extract_field(pkg_data, "name")
            if not name or not isinstance(name, str) or not name.strip():
                msg = f"Skipping package record missing valid name: {pkg_data!r}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            name = name.strip()
            version = extract_field(pkg_identity, "version") or extract_field(pkg_data, ("resolved_version", "version"))
            purl = extract_field(pkg_identity, "purl") or extract_field(pkg_data, "purl")
            cpe = extract_field(pkg_identity, "cpe") or extract_field(pkg_data, "cpe")
            ecosystem_raw = extract_field(pkg_identity, "ecosystem") or extract_field(pkg_data, "ecosystem", "unknown")
            ecosystem = ecosystem_raw.value if hasattr(ecosystem_raw, "value") else str(ecosystem_raw or "unknown")

            # Create Canonical Package Property
            cp = CanonicalPackage(
                name=name,
                ecosystem=ecosystem,
                version=str(version) if version is not None else None,
                purl=str(purl) if purl else None,
                cpe=str(cpe) if cpe else None,
                dependency_scope=extract_field(pkg_data, "scope"),
                directness=extract_field(pkg_data, "dependency_type")
            )

            identifiers = []
            if purl:
                identifiers.append(Identifier(type="purl", value=str(purl)))
            if cpe:
                identifiers.append(Identifier(type="cpe", value=str(cpe)))

            locations = []
            manifest = extract_field(pkg_data, ("manifest_file", "resolution_source", "source_file"))
            if manifest:
                locations.append(Location(type="file", value=str(manifest)))

            asset = CanonicalAsset(
                scan_id=ctx.scan_id,
                asset_type=AssetType.PACKAGE,
                name=name,
                version=str(version) if version is not None else None,
                identifiers=identifiers,
                locations=locations,
                observed_at=now,
                sources=[self.engine_name],
                properties={"package_data": cp.model_dump(exclude_none=True)}
            )
            assets.append(asset)

            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type="package_dependency",
                target=name,
                location=str(manifest) if manifest else None,
                observed_at=now,
                value=str(purl or version or name)
            )
            evidence.append(ev)
            asset.evidence_refs.append(ev.evidence_id)

        # Handle sca_findings (vulnerabilities associated with packages)
        for sca_finding in getattr(ctx, "sca_findings", []):
            if not isinstance(sca_finding, dict) and not hasattr(sca_finding, "package") and not hasattr(sca_finding, "library_name"):
                msg = f"Skipping malformed SCA finding record: invalid type {type(sca_finding).__name__}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            # Extract package details
            pkg_identity = extract_field(sca_finding, "package")
            if pkg_identity:
                pkg_name = extract_field(pkg_identity, "name") or extract_field(sca_finding, "library_name", "unknown")
                pkg_purl = extract_field(pkg_identity, "purl")
                pkg_version = extract_field(sca_finding, "resolved_version") or extract_field(pkg_identity, "version")
            else:
                pkg_name = extract_field(sca_finding, ("library_name", "package_name", "name"), "unknown")
                pkg_purl = extract_field(sca_finding, "purl")
                pkg_version = extract_field(sca_finding, "version")

            vuln_id = extract_field(sca_finding, ("vulnerability_id", "cve_id"), "UNKNOWN-VULN")
            manifest = extract_field(sca_finding, ("manifest_file", "resolution_source", "source_file"))
            
            # Evidence
            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type="vulnerability_match",
                target=str(pkg_name or "unknown"),
                location=str(manifest) if manifest else None,
                observed_at=now,
                value=str(vuln_id)
            )
            evidence.append(ev)
            
            # Severity
            sev_raw = extract_field(sca_finding, "severity", "info")
            if sev_raw and isinstance(sev_raw, str):
                sev_raw = sev_raw.upper()
                if sev_raw in [r.value for r in RiskLevel]:
                    severity = RiskLevel(sev_raw)
                elif sev_raw in ("INFO", "NONE"):
                    severity = RiskLevel.SAFE
                else:
                    severity = RiskLevel.UNKNOWN
            else:
                severity = RiskLevel.UNKNOWN

            cvss = extract_field(sca_finding, "cvss")
            cvss_score = extract_field(cvss, "base_score") or extract_field(sca_finding, "cvss_score")
            cvss_vector = extract_field(cvss, "vector") or extract_field(sca_finding, "cvss_vector")

            # Finding
            cf = CanonicalFinding(
                scan_id=ctx.scan_id,
                finding_type="vulnerability",
                title=f"{vuln_id} in {pkg_name}",
                description=f"Package {pkg_name} ({pkg_version}) is vulnerable to {vuln_id}.",
                severity=severity,
                status=ObservationStatus.OBSERVED,
                source=[self.engine_name],
                evidence_refs=[ev.evidence_id],
                details={
                    "vulnerability_id": vuln_id,
                    "package_name": pkg_name,
                    "version": pkg_version,
                    "purl": pkg_purl,
                    "crypto_relevance": extract_field(sca_finding, "crypto_relevance"),
                    "fixed_versions": extract_field(sca_finding, "fixed_versions", []),
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "cwe": extract_field(sca_finding, "cwe", []),
                }
            )
            
            # References
            if vuln_id and str(vuln_id).startswith("CVE"):
                cf.references.append({"type": "cve", "id": str(vuln_id)})
                
            findings.append(cf)

        return assets, findings, evidence
