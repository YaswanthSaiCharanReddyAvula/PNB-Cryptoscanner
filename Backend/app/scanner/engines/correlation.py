"""
QuantumShield — Correlation + Risk Scoring Engine (Stage 11)

Builds the unified asset-intelligence graph, derives attack paths,
computes per-asset and estate-level risk scores, and generates scan
diffs.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Optional

from app.scanner.models import (
    AssetGraph,
    AssetIntelligence,
    AssetRiskScore,
    GraphEdge,
    GraphNode,
    RiskDriver,
    ScanDiff,
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

DIMENSION_WEIGHTS = {
    "crypto":       0.20,
    "network":      0.15,
    "software":     0.15,
    "web_security": 0.15,
    "attack_surface": 0.15,
    "infrastructure": 0.10,
    "cve":          0.10,
}


class CorrelationRiskEngine(ScanStage):
    name = "correlation"
    order = 11
    timeout_seconds = 30
    max_retries = 0
    criticality = StageCriticality.IMPORTANT
    required_fields = ["subdomains"]
    writes_fields = ["graph", "risk_scores", "all_findings"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        graph = self._build_graph(ctx)
        risk_scores = self._score_assets(ctx)
        intel = self._build_asset_intelligence(ctx, risk_scores)
        diff = await self._compute_diff(ctx)
        all_findings = self._collect_all_findings(ctx)

        return StageResult(
            status="completed",
            data={
                "graph": graph.model_dump(),
                "risk_scores": [r.model_dump() for r in risk_scores],
                "all_findings": all_findings,
                "asset_intelligence": [a.model_dump() for a in intel],
                "scan_diff": diff.model_dump() if diff else None,
            },
        )

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self, ctx: ScanContext) -> AssetGraph:
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        seen_nodes: set[str] = set()

        root_id = f"domain:{ctx.domain}"
        nodes.append(GraphNode(id=root_id, node_type="domain", label=ctx.domain))
        seen_nodes.add(root_id)

        for sub in (ctx.subdomains or []):
            host = sub if isinstance(sub, str) else (sub.get("hostname") if isinstance(sub, dict) else str(sub))
            host = (host or "").strip().lower()
            if not host:
                continue
            nid = f"host:{host}"
            if nid not in seen_nodes:
                nodes.append(GraphNode(id=nid, node_type="subdomain", label=host))
                seen_nodes.add(nid)
                edges.append(GraphEdge(source=root_id, target=nid, relationship="has_subdomain"))

        for host, ips in (ctx.ip_map or {}).items():
            host_id = f"host:{host}"
            for ip in ips:
                ip_id = f"ip:{ip}"
                if ip_id not in seen_nodes:
                    nodes.append(GraphNode(id=ip_id, node_type="ip", label=ip))
                    seen_nodes.add(ip_id)
                if host_id in seen_nodes:
                    edges.append(GraphEdge(source=host_id, target=ip_id, relationship="resolves_to"))

        for svc in (ctx.services or []):
            s = svc if isinstance(svc, dict) else {}
            host = s.get("host", "")
            port = s.get("port", "")
            svc_id = f"svc:{host}:{port}"
            if svc_id not in seen_nodes:
                nodes.append(GraphNode(
                    id=svc_id, node_type="service",
                    label=f"{s.get('service_name', 'unknown')}:{port}",
                    properties={"port": port, "product": s.get("product")},
                ))
                seen_nodes.add(svc_id)
            host_id = f"host:{host}"
            if host_id in seen_nodes:
                edges.append(GraphEdge(source=host_id, target=svc_id, relationship="runs"))

        for tp in (ctx.tls_profiles or []):
            t = tp if isinstance(tp, dict) else {}
            cert = t.get("leaf_cert") or {}
            fp = cert.get("fingerprint_sha256", "")[:16]
            if fp:
                cert_id = f"cert:{fp}"
                if cert_id not in seen_nodes:
                    nodes.append(GraphNode(
                        id=cert_id, node_type="certificate",
                        label=f"Cert {cert.get('subject', '')[:40]}",
                        properties={
                            "key_type": cert.get("key_type"),
                            "key_size": cert.get("key_size"),
                            "expires": cert.get("valid_to"),
                        },
                    ))
                    seen_nodes.add(cert_id)
                host_id = f"host:{t.get('host', '')}"
                if host_id in seen_nodes:
                    edges.append(GraphEdge(source=host_id, target=cert_id, relationship="presents"))

        for vf in (ctx.vuln_findings or []):
            v = vf if isinstance(vf, dict) else {}
            vid = v.get("vuln_id", "")
            host = v.get("host", "")
            fid = f"finding:{vid}:{host}"
            if fid not in seen_nodes:
                nodes.append(GraphNode(
                    id=fid, node_type="finding",
                    label=v.get("name", vid),
                    properties={"severity": v.get("severity"), "category": v.get("category")},
                ))
                seen_nodes.add(fid)
            host_id = f"host:{host}"
            if host_id in seen_nodes:
                edges.append(GraphEdge(source=host_id, target=fid, relationship="affected_by", weight=0.9))

        return AssetGraph(nodes=nodes, edges=edges)

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _score_assets(self, ctx: ScanContext) -> list[AssetRiskScore]:
        scores: list[AssetRiskScore] = []
        hosts = [
            h if isinstance(h, str) else (h.get("hostname") if isinstance(h, dict) else str(h))
            for h in (ctx.subdomains or [])
        ]
        hosts = [(h or "").strip().lower() for h in hosts if (h or "").strip()]
        for host in hosts:
            dims = self._dimension_scores(host, ctx)
            overall = sum(dims[d] * DIMENSION_WEIGHTS[d] for d in DIMENSION_WEIGHTS)
            overall = max(0.0, min(100.0, overall))
            level = (
                "critical" if overall < 30
                else "high" if overall < 50
                else "medium" if overall < 70
                else "low" if overall < 85
                else "safe"
            )
            drivers = self._top_drivers(host, ctx)
            scores.append(AssetRiskScore(
                host=host,
                overall_score=round(overall, 1),
                risk_level=level,
                dimension_scores=dims,
                top_risk_drivers=drivers,
                remediation_priority=1 if level in ("critical", "high") else 2 if level == "medium" else 3,
            ))
        return sorted(scores, key=lambda s: s.overall_score)

    def _dimension_scores(self, host: str, ctx: ScanContext) -> dict[str, float]:
        crypto = 80.0
        for cf in (ctx.crypto_findings or []):
            c = cf if isinstance(cf, dict) else {}
            if c.get("host") == host:
                penalty = {"critical": 25, "high": 15, "medium": 8, "low": 3}.get(c.get("quantum_risk", ""), 5)
                crypto = max(0, crypto - penalty)

        network = 90.0
        open_count = sum(
            1 for s in (ctx.services or [])
            if (s if isinstance(s, dict) else {}).get("host") == host and
               (s if isinstance(s, dict) else {}).get("state") == "open"
        )
        network -= min(40, open_count * 4)
        db_ports = sum(
            1 for s in (ctx.services or [])
            if (s if isinstance(s, dict) else {}).get("host") == host and
               (s if isinstance(s, dict) else {}).get("protocol_category") == "db"
        )
        network -= db_ports * 15

        software = 80.0
        for t in (ctx.tech_fingerprints or []):
            td = t if isinstance(t, dict) else {}
            if td.get("host") == host and td.get("cpe"):
                software -= 5

        web_sec = 80.0
        for w in (ctx.web_profiles or []):
            wd = w if isinstance(w, dict) else {}
            if wd.get("host") == host:
                web_sec = wd.get("header_score", 80.0)

        surface = 90.0
        hidden_count = sum(
            1 for h in (ctx.hidden_findings or [])
            if (h if isinstance(h, dict) else {}).get("host") == host
        )
        surface -= min(60, hidden_count * 8)

        infra = 70.0
        for i in (ctx.cdn_waf_intel or []):
            ii = i if isinstance(i, dict) else {}
            if ii.get("host") == host:
                if ii.get("waf_detected"):
                    infra += 15
                if ii.get("cdn_provider"):
                    infra += 10

        cve_score = 90.0
        for v in (ctx.vuln_findings or []):
            vd = v if isinstance(v, dict) else {}
            if vd.get("host") == host:
                cve_penalty = {"critical": 20, "high": 12, "medium": 6, "low": 2}.get(vd.get("severity", ""), 3)
                cve_score = max(0, cve_score - cve_penalty)

        return {
            "crypto": max(0, min(100, crypto)),
            "network": max(0, min(100, network)),
            "software": max(0, min(100, software)),
            "web_security": max(0, min(100, web_sec)),
            "attack_surface": max(0, min(100, surface)),
            "infrastructure": max(0, min(100, infra)),
            "cve": max(0, min(100, cve_score)),
        }

    @staticmethod
    def _top_drivers(host: str, ctx: ScanContext) -> list[RiskDriver]:
        drivers: list[RiskDriver] = []
        for vf in (ctx.vuln_findings or []):
            v = vf if isinstance(vf, dict) else {}
            if v.get("host") == host and v.get("severity") in ("critical", "high"):
                drivers.append(RiskDriver(
                    dimension=v.get("category", ""),
                    finding=v.get("name", ""),
                    impact=v.get("severity", ""),
                    confidence=str(v.get("confidence", "")),
                    remediation=v.get("remediation", ""),
                ))
        return drivers[:5]

    # ------------------------------------------------------------------
    # Asset Intelligence assembly
    # ------------------------------------------------------------------

    def _build_asset_intelligence(self, ctx: ScanContext, scores: list[AssetRiskScore]) -> list[AssetIntelligence]:
        score_map = {s.host: s for s in scores}
        intel: list[AssetIntelligence] = []
        hosts = [
            h if isinstance(h, str) else (h.get("hostname") if isinstance(h, dict) else str(h))
            for h in (ctx.subdomains or [])
        ]
        hosts = [(h or "").strip().lower() for h in hosts if (h or "").strip()]
        for host in hosts:
            ips = (ctx.ip_map or {}).get(host, [])
            svcs = [s for s in (ctx.services or []) if (s if isinstance(s, dict) else {}).get("host") == host]
            tls = [t for t in (ctx.tls_profiles or []) if (t if isinstance(t, dict) else {}).get("host") == host]
            cf = [c for c in (ctx.crypto_findings or []) if (c if isinstance(c, dict) else {}).get("host") == host]
            techs = [t for t in (ctx.tech_fingerprints or []) if (t if isinstance(t, dict) else {}).get("host") == host]
            hid = [h for h in (ctx.hidden_findings or []) if (h if isinstance(h, dict) else {}).get("host") == host]
            vulns = [v for v in (ctx.vuln_findings or []) if (v if isinstance(v, dict) else {}).get("host") == host]

            infra_list = [i for i in (ctx.cdn_waf_intel or []) if (i if isinstance(i, dict) else {}).get("host") == host]
            os_list = [o for o in (ctx.os_fingerprints or []) if (o if isinstance(o, dict) else {}).get("host") == host]
            web_list = [w for w in (ctx.web_profiles or []) if (w if isinstance(w, dict) else {}).get("host") == host]

            intel.append(AssetIntelligence(
                hostname=host,
                ip_addresses=ips,
                open_ports=[s.get("port") for s in svcs if isinstance(s, dict) and s.get("state") == "open"],
                services=svcs,
                os_fingerprint=os_list[0] if os_list else None,
                tls_profiles=tls,
                crypto_findings=cf,
                technologies=techs,
                infrastructure=infra_list[0] if infra_list else None,
                web_profile=web_list[0] if web_list else None,
                hidden_findings=hid,
                vuln_findings=vulns,
                risk_score=score_map.get(host),
            ))
        return intel

    # ------------------------------------------------------------------
    # Scan diff
    # ------------------------------------------------------------------

    async def _compute_diff(self, ctx: ScanContext) -> Optional[ScanDiff]:
        try:
            db = ctx.db
            if db is None:
                return None
            prev = await db["scans"].find_one(
                {"domain": ctx.domain, "status": "completed"},
                sort=[("completed_at", -1)],
            )
            if not prev:
                return None

            prev_hosts = {a.get("subdomain", "") for a in prev.get("assets", [])}
            curr_hosts = {
                ((h if isinstance(h, str) else (h.get("hostname") if isinstance(h, dict) else str(h))) or "").strip().lower()
                for h in (ctx.subdomains or [])
            }
            curr_hosts.discard("")

            return ScanDiff(
                new_assets=sorted(curr_hosts - prev_hosts),
                removed_assets=sorted(prev_hosts - curr_hosts),
                new_findings=[],
                resolved_findings=[],
                score_delta=0.0,
            )
        except Exception:
            logger.debug("Scan diff failed", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # Collect all findings into unified list
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_all_findings(ctx: ScanContext) -> list[dict]:
        unified: list[dict] = []
        for src_name, src_list in [
            ("crypto", ctx.crypto_findings),
            ("vuln", ctx.vuln_findings),
            ("hidden", ctx.hidden_findings),
        ]:
            for item in (src_list or []):
                d = item if isinstance(item, dict) else {}
                d["_finding_type"] = f"{src_name}_finding"
                unified.append(d)
        unified.sort(
            key=lambda f: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.get("severity", "info"), 5),
                -(f.get("confidence", 0) if isinstance(f.get("confidence"), (int, float)) else 0),
            )
        )
        return unified
