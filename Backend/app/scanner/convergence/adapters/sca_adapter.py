"""
QuantumShield — Convergence SCA Adapter

Transforms SCA package findings and vulnerabilities into canonical models.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter
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
            # The structure of pkg_data depends on how SCA populates it. Let's assume it resembles SCADependency or PackageIdentity.
            if hasattr(pkg_data, "package"):
                identity = pkg_data.package
            else:
                identity = pkg_data

            name = getattr(identity, "name", "unknown_package")
            version = getattr(identity, "version", None) or getattr(pkg_data, "resolved_version", None)
            purl = getattr(identity, "purl", None)
            cpe = getattr(identity, "cpe", None)
            ecosystem = getattr(identity, "ecosystem", "unknown")
            if hasattr(ecosystem, "value"):
                ecosystem = ecosystem.value

            # Create Canonical Package Property
            cp = CanonicalPackage(
                name=name,
                ecosystem=ecosystem,
                version=version,
                purl=purl,
                cpe=cpe,
                dependency_scope=getattr(pkg_data, "scope", None),
                directness=getattr(pkg_data, "dependency_type", None)
            )

            identifiers = []
            if purl:
                identifiers.append(Identifier(type="purl", value=purl))
            if cpe:
                identifiers.append(Identifier(type="cpe", value=cpe))

            locations = []
            manifest = getattr(pkg_data, "manifest_file", None) or getattr(pkg_data, "resolution_source", None)
            if manifest:
                locations.append(Location(type="file", value=manifest))

            asset = CanonicalAsset(
                scan_id=ctx.scan_id,
                asset_type=AssetType.PACKAGE,
                name=name,
                version=version,
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
                location=manifest,
                observed_at=now,
                value=purl or version
            )
            evidence.append(ev)
            asset.evidence_refs.append(ev.evidence_id)


        # Handle sca_findings (vulnerabilities associated with packages)
        for sca_finding in getattr(ctx, "sca_findings", []):
            # Extract package details
            if hasattr(sca_finding, "package"):
                pkg_identity = sca_finding.package
                pkg_name = getattr(pkg_identity, "name", "unknown")
                pkg_purl = getattr(pkg_identity, "purl", None)
                pkg_version = getattr(sca_finding, "resolved_version", None)
            else:
                pkg_name = getattr(sca_finding, "library_name", "unknown")
                pkg_purl = None
                pkg_version = getattr(sca_finding, "version", None)

            vuln_id = getattr(sca_finding, "vulnerability_id", "UNKNOWN-VULN")
            
            # Evidence
            manifest = getattr(sca_finding, "manifest_file", None)
            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type="vulnerability_match",
                target=pkg_name,
                location=manifest,
                observed_at=now,
                value=vuln_id
            )
            evidence.append(ev)
            
            # Severity
            sev_raw = getattr(sca_finding, "severity", "info")
            if sev_raw and isinstance(sev_raw, str):
                sev_raw = sev_raw.upper()
                if sev_raw in [r.value for r in RiskLevel]:
                    severity = RiskLevel(sev_raw)
                elif sev_raw == "INFO":
                    severity = RiskLevel.SAFE
                else:
                    severity = RiskLevel.UNKNOWN
            else:
                severity = RiskLevel.UNKNOWN

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
                    "crypto_relevance": getattr(sca_finding, "crypto_relevance", None),
                    "fixed_versions": getattr(sca_finding, "fixed_versions", []),
                    "cvss_score": getattr(getattr(sca_finding, "cvss", None), "base_score", None),
                    "cvss_vector": getattr(getattr(sca_finding, "cvss", None), "vector", None),
                    "cwe": getattr(sca_finding, "cwe", []),
                }
            )
            
            # References
            if vuln_id and vuln_id.startswith("CVE"):
                cf.references.append({"type": "cve", "id": vuln_id})
                
            findings.append(cf)

        return assets, findings, evidence
