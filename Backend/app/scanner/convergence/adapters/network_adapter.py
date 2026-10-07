"""
QuantumShield — Convergence Network Adapter

Transforms network services and OS fingerprints into canonical models.
"""

from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter
from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
    Identifier,
    Location,
)
from app.scanner.convergence.enums import AssetType
from app.scanner.convergence.normalizers import normalize_hostname, normalize_port
from app.scanner.pipeline import ScanContext


class NetworkAdapter(EngineAdapter):
    @property
    def engine_name(self) -> str:
        return "network_engine"

    @property
    def engine_stage(self) -> str:
        return "discovery/network"

    def process(self, ctx: ScanContext) -> Tuple[List[CanonicalAsset], List[CanonicalFinding], List[CanonicalEvidence]]:
        assets: List[CanonicalAsset] = []
        findings: List[CanonicalFinding] = []
        evidence: List[CanonicalEvidence] = []
        
        now = datetime.now(timezone.utc)

        # Services
        for svc in getattr(ctx, "services", []):
            # svc could be dict or PortResult/ServiceFingerprint model
            host = normalize_hostname(getattr(svc, "ip", getattr(svc, "host", "")))
            port_raw = getattr(svc, "port", 0)
            transport_raw = getattr(svc, "protocol", "tcp")
            if isinstance(svc, dict):
                host = normalize_hostname(svc.get("ip", svc.get("host", "")))
                port_raw = svc.get("port", 0)
                transport_raw = svc.get("protocol", "tcp")
                
            port_info = normalize_port(port_raw, transport_raw)
            
            asset = CanonicalAsset(
                scan_id=ctx.scan_id,
                asset_type=AssetType.SERVICE,
                name=f"Service {host}:{port_info['port']}/{port_info['transport']}",
                identifiers=[
                    Identifier(type="hostname", value=host),
                    Identifier(type="port", value=str(port_info["port"]))
                ],
                locations=[
                    Location(type="endpoint", value=f"{host}:{port_info['port']}")
                ],
                observed_at=now,
                sources=[self.engine_name]
            )
            assets.append(asset)
            
            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type="port_scan",
                target=host,
                observed_at=now,
                value=f"{port_info['port']}/{port_info['transport']}"
            )
            evidence.append(ev)
            asset.evidence_refs.append(ev.evidence_id)
            
        # OS Fingerprints
        for os_fp in getattr(ctx, "os_fingerprints", []):
            host = normalize_hostname(getattr(os_fp, "host", ""))
            if isinstance(os_fp, dict):
                host = normalize_hostname(os_fp.get("host", ""))
                os_match = os_fp.get("os_match", "unknown_os")
            else:
                os_match = getattr(os_fp, "os_match", "unknown_os")
                
            # Treat OS as an asset or property of host. We'll make it an OS/Framework asset.
            asset = CanonicalAsset(
                scan_id=ctx.scan_id,
                asset_type=AssetType.FRAMEWORK,
                name=os_match,
                properties={"os": True},
                observed_at=now,
                sources=[self.engine_name]
            )
            assets.append(asset)
            
            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type="os_fingerprint",
                target=host,
                observed_at=now,
                value=os_match
            )
            evidence.append(ev)
            asset.evidence_refs.append(ev.evidence_id)

        return assets, findings, evidence
