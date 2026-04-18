"""
QuantumShield — Pipeline Manager

Orchestrates all scan stages in declared order, handles retries,
criticality-based cascading failures, result merging, and AI hooks.
"""

from __future__ import annotations

import inspect
import time
import uuid
from typing import Any, Callable, Optional

from app.config import settings
from app.scanner.models import StageMetrics, StageResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class StageCriticality:
    CRITICAL = "critical"
    IMPORTANT = "important"
    OPTIONAL = "optional"


class MergeStrategy:
    APPEND = "append"
    OVERWRITE = "overwrite"
    DEDUPLICATE = "deduplicate"


STAGE_TIMEOUTS: dict[str, int] = {
    "recon": 120,
    "network": 120,
    "os_fingerprint": 45,
    "tls_engine": 90,
    "crypto_analysis": 30,
    "cdn_waf": 45,
    "tech_fingerprint": 45,
    "web_discovery": 60,
    "hidden_discovery": 90,
    "vuln_engine": 60,
    "correlation": 30,
    "reporting": 30,
    "advanced_fingerprint": 60,
    "attack_surface": 180,
    "behavioral": 60,
    "browser_engine": 120,
}


# ---------------------------------------------------------------------------
# ScanStage — abstract base for every pipeline stage
# ---------------------------------------------------------------------------

class ScanStage:
    name: str = ""
    order: int = 0
    timeout_seconds: int = 120
    max_retries: int = 1
    criticality: str = StageCriticality.IMPORTANT
    required_fields: list[str] = []
    writes_fields: list[str] = []
    merge_strategy: str = MergeStrategy.APPEND

    async def execute(self, ctx: ScanContext) -> StageResult:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# ScanContext — mutable state bag carried through the pipeline
# ---------------------------------------------------------------------------

class ScanContext:

    def __init__(
        self,
        scan_id: str | None = None,
        domain: str = "",
        options: dict | None = None,
        *,
        throttle: Any = None,
        broadcast: Callable[..., Any] | None = None,
        db: Any = None,
    ):
        self.scan_id: str = scan_id or str(uuid.uuid4())
        self.domain: str = domain
        self.options: dict = options or {}

        # --- Recon / network layer ---
        self.subdomains: list[dict] = []
        self.ip_map: dict[str, Any] = {}
        self.dns_records: list[dict] = []
        self.whois: Optional[dict] = None
        self.assets: list[dict] = []
        self.services: list[dict] = []

        # --- Fingerprinting / TLS / crypto ---
        self.os_fingerprints: list[dict] = []
        self.tls_profiles: list[dict] = []
        self.crypto_findings: list[dict] = []
        self.cdn_waf_intel: list[dict] = []

        # --- Web / tech ---
        self.tech_fingerprints: list[dict] = []
        self.web_profiles: list[dict] = []
        self.hidden_findings: list[dict] = []
        self.vuln_findings: list[dict] = []

        # --- Aggregated ---
        self.all_findings: list[dict] = []
        self.graph: Optional[dict] = None
        self.risk_scores: list[dict] = []
        self.cbom: dict = {}
        self.recommendations: list[dict] = []
        self.executive_summary: str = ""
        self.quantum_score: dict = {}
        self.estate_tier: str = "Unknown"

        # --- Adaptive state (AI-driven prioritisation) ---
        self.extra_hidden_paths: list[str] = []
        self.hosts_for_full_cipher_enum: set[str] = set()
        self.hosts_for_browser_scan: set[str] = set()
        self.hosts_for_deep_fuzz: set[str] = set()
        self.hosts_for_graphql_deep: set[str] = set()
        self.hosts_for_auth_test: set[str] = set()
        self.deprioritized_hosts: set[str] = set()
        self.active_hosts: list[str] = []
        self.all_hosts: list[str] = []

        # --- Infrastructure handles ---
        self.throttle = throttle
        self.broadcast: Callable[..., Any] = broadcast or (lambda *a, **kw: None)
        self.db = db

    def has(self, fields: list[str]) -> bool:
        """Return True when every listed attribute is present and non-empty."""
        for f in fields:
            val = getattr(self, f, None)
            if val is None:
                return False
            if isinstance(val, (list, dict, set, str)) and len(val) == 0:
                return False
        return True


# ---------------------------------------------------------------------------
# PipelineManager
# ---------------------------------------------------------------------------

class PipelineManager:

    def __init__(
        self,
        stages: list[ScanStage],
        ai_adaptive: Any = None,
        scheduler: Any = None,
    ):
        self.stages = sorted(stages, key=lambda s: s.order)
        self.ai = ai_adaptive
        self.scheduler = scheduler
        self.metrics: list[StageMetrics] = []

        from app.scanner.retry import RetryManager
        self.retry = RetryManager()

    # ---- main loop --------------------------------------------------------

    async def run(self, ctx: ScanContext) -> dict:
        skipped_due_to: set[str] = set()

        for stage in self.stages:
            if ctx.db is not None:
                doc = await ctx.db["scans"].find_one({"scan_id": ctx.scan_id}, projection={"status": 1})
                if doc and doc.get("status") not in ("running", "pending"):
                    logger.info("Scan %s status changed to %s in DB, stopping pipeline.", ctx.scan_id, doc.get("status"))
                    break

            if stage.required_fields and not ctx.has(stage.required_fields):
                logger.warning(
                    "Stage %s skipped: missing required fields %s",
                    stage.name, stage.required_fields,
                )
                self.metrics.append(StageMetrics(
                    name=stage.name, status="skipped",
                    reason="missing required fields",
                ))
                if stage.criticality == StageCriticality.CRITICAL:
                    skipped_due_to.add(stage.name)
                continue

            if any(dep in skipped_due_to for dep in stage.required_fields):
                logger.warning(
                    "Stage %s skipped: upstream critical dependency failed",
                    stage.name,
                )
                self.metrics.append(StageMetrics(
                    name=stage.name, status="skipped",
                    reason="upstream dependency failed",
                ))
                continue

            if self.scheduler and self.scheduler.should_stop():
                logger.info("Scheduler requested early stop before stage %s", stage.name)
                break

            maybe_awaitable = ctx.broadcast("scan_progress", {
                "scan_id": ctx.scan_id,
                "stage": stage.name,
                "status": "running",
            })
            if inspect.isawaitable(maybe_awaitable):
                await maybe_awaitable

            t0 = time.time()
            result = await self.retry.execute(
                stage, ctx, max_retries=stage.max_retries,
            )
            duration = time.time() - t0

            if result.status in ("error", "timeout"):
                if stage.criticality == StageCriticality.CRITICAL:
                    logger.error(
                        "CRITICAL stage %s failed — cascading skip", stage.name,
                    )
                    skipped_due_to.add(stage.name)
                elif stage.criticality == StageCriticality.IMPORTANT:
                    logger.warning(
                        "IMPORTANT stage %s failed — continuing (error=%s)",
                        stage.name,
                        (result.error or "unknown")[:300],
                    )
                else:
                    logger.info("OPTIONAL stage %s failed — ignored", stage.name)
            else:
                self._merge(ctx, stage, result)

            summary, preview = self._build_stage_summary(stage.name, ctx, result)
            self.metrics.append(StageMetrics(
                name=stage.name,
                status=result.status,
                duration=duration,
                request_count=result.request_count,
                error=result.error,
                summary=summary,
                preview=preview,
            ))

            if settings.SCANNER_STAGE_VERBOSE_LOGS:
                log_payload = {
                    "scan_id": ctx.scan_id,
                    "stage": stage.name,
                    "status": result.status,
                    "duration_ms": int(duration * 1000),
                    "request_count": result.request_count,
                    "summary": summary,
                    "preview": preview,
                }
                if result.error:
                    log_payload["error"] = self._truncate(
                        result.error, settings.SCANNER_STAGE_MESSAGE_MAX_LEN,
                    )
                logger.info("Stage complete | %s", log_payload)

            if settings.SCANNER_STAGE_WS_SUMMARY:
                ws_payload = {
                    "scan_id": ctx.scan_id,
                    "stage": stage.name,
                    "status": result.status,
                    "duration_ms": int(duration * 1000),
                    "request_count": result.request_count,
                    "summary": summary,
                    "preview": preview,
                }
                if result.error:
                    ws_payload["error"] = self._truncate(
                        result.error, settings.SCANNER_STAGE_MESSAGE_MAX_LEN,
                    )
                maybe_awaitable = ctx.broadcast("stage_complete", ws_payload)
                if inspect.isawaitable(maybe_awaitable):
                    await maybe_awaitable

            await self._persist_stage(
                ctx, stage.name, result, duration, summary=summary, preview=preview,
            )

            if self.ai:
                try:
                    summary = self._summarize_stage_findings(stage.name, result)
                    ai_directives = await self.ai.after_stage(
                        stage.name, summary, self._summarize_context(ctx),
                    )
                    if ai_directives:
                        self._apply_ai_directives(ctx, ai_directives)
                except Exception:
                    logger.exception("AI adaptive hook failed for stage %s", stage.name)

        self._confidence_filter(ctx)
        return self._build_final(ctx)

    # ---- merging ----------------------------------------------------------

    def _merge(self, ctx: ScanContext, stage: ScanStage, result: StageResult) -> None:
        for field in stage.writes_fields:
            incoming = result.data.get(field)
            if incoming is None:
                continue
            current = getattr(ctx, field, None)

            if stage.merge_strategy == MergeStrategy.OVERWRITE:
                setattr(ctx, field, incoming)
            elif stage.merge_strategy == MergeStrategy.DEDUPLICATE:
                if isinstance(current, list) and isinstance(incoming, list):
                    seen = {self._dedup_key(i) for i in current}
                    for item in incoming:
                        key = self._dedup_key(item)
                        if key not in seen:
                            current.append(item)
                            seen.add(key)
                else:
                    setattr(ctx, field, incoming)
            else:  # APPEND (default)
                if isinstance(current, list) and isinstance(incoming, list):
                    current.extend(incoming)
                else:
                    setattr(ctx, field, incoming)

    @staticmethod
    def _dedup_key(item: Any) -> str:
        if isinstance(item, dict):
            return (
                f"{item.get('host', '')}-{item.get('port', '')}-{item.get('path', '')}"
            )
        return str(item)

    # ---- persistence ------------------------------------------------------

    async def _persist_stage(
        self,
        ctx: ScanContext,
        stage_name: str,
        result: StageResult,
        duration: float,
        *,
        summary: Optional[dict] = None,
        preview: Optional[dict] = None,
    ) -> None:
        if ctx.db is None:
            return
        try:
            stage_doc = {
                "name": stage_name,
                "status": result.status,
                "duration": duration,
                "request_count": result.request_count,
                "error": result.error,
            }
            if settings.SCANNER_STAGE_DB_SUMMARY:
                stage_doc["summary"] = summary or {}
                stage_doc["preview"] = preview or {}
            await ctx.db.scans.update_one(
                {"scan_id": ctx.scan_id},
                {"$push": {"stages": stage_doc}},
                upsert=True,
            )
        except Exception:
            logger.exception("Failed to persist stage %s", stage_name)

    # ---- final report -----------------------------------------------------

    def _build_final(self, ctx: ScanContext) -> dict:
        return {
            "scan_id": ctx.scan_id,
            "domain": ctx.domain,
            "subdomains": ctx.subdomains,
            "ip_map": ctx.ip_map,
            "dns_records": ctx.dns_records,
            "whois": ctx.whois,
            "assets": ctx.assets,
            "services": ctx.services,
            "os_fingerprints": ctx.os_fingerprints,
            "tls_profiles": ctx.tls_profiles,
            "crypto_findings": ctx.crypto_findings,
            "cdn_waf_intel": ctx.cdn_waf_intel,
            "tech_fingerprints": ctx.tech_fingerprints,
            "web_profiles": ctx.web_profiles,
            "hidden_findings": ctx.hidden_findings,
            "vuln_findings": ctx.vuln_findings,
            "all_findings": ctx.all_findings,
            "graph": ctx.graph,
            "risk_scores": ctx.risk_scores,
            "cbom": ctx.cbom,
            "recommendations": ctx.recommendations,
            "executive_summary": ctx.executive_summary,
            "quantum_score": ctx.quantum_score,
            "estate_tier": ctx.estate_tier,
            "stage_metrics": [m.model_dump() for m in self.metrics],
        }

    # ---- AI helpers -------------------------------------------------------

    @staticmethod
    def _summarize_stage_findings(stage_name: str, result: StageResult) -> dict:
        return {
            "stage": stage_name,
            "status": result.status,
            "finding_count": len(result.data) if isinstance(result.data, list) else 1,
            "error": result.error,
        }

    @staticmethod
    def _summarize_context(ctx: ScanContext) -> dict:
        return {
            "subdomains": len(ctx.subdomains),
            "services": len(ctx.services),
            "tls_profiles": len(ctx.tls_profiles),
            "crypto_findings": len(ctx.crypto_findings),
            "vuln_findings": len(ctx.vuln_findings),
            "all_findings": len(ctx.all_findings),
        }

    # ---- AI directives application ----------------------------------------

    @staticmethod
    def _apply_ai_directives(ctx: ScanContext, directives: dict) -> None:
        if paths := directives.get("extra_hidden_paths"):
            ctx.extra_hidden_paths.extend(paths)
        if hosts := directives.get("hosts_for_full_cipher_enum"):
            ctx.hosts_for_full_cipher_enum.update(hosts)
        if hosts := directives.get("hosts_for_browser_scan"):
            ctx.hosts_for_browser_scan.update(hosts)
        if hosts := directives.get("hosts_for_deep_fuzz"):
            ctx.hosts_for_deep_fuzz.update(hosts)
        if hosts := directives.get("hosts_for_graphql_deep"):
            ctx.hosts_for_graphql_deep.update(hosts)
        if hosts := directives.get("hosts_for_auth_test"):
            ctx.hosts_for_auth_test.update(hosts)
        if hosts := directives.get("deprioritized_hosts"):
            ctx.deprioritized_hosts.update(hosts)

    # ---- post-processing --------------------------------------------------

    @staticmethod
    def _confidence_filter(ctx: ScanContext, min_confidence: float = 0.0) -> None:
        """Drop any findings below the minimum confidence threshold."""
        if min_confidence <= 0.0:
            return
        for attr in ("all_findings", "vuln_findings", "crypto_findings"):
            items: list = getattr(ctx, attr, [])
            filtered = [
                f for f in items
                if not isinstance(f, dict) or f.get("confidence", 1.0) >= min_confidence
            ]
            setattr(ctx, attr, filtered)

    @staticmethod
    def _truncate(value: Any, max_len: int) -> str:
        text = str(value or "")
        if max_len <= 0:
            return text
        if len(text) <= max_len:
            return text
        return f"{text[:max_len]}..."

    def _safe_preview_list(self, values: Any, n: int) -> list:
        if not isinstance(values, list):
            return []
        limit = max(0, n)
        out: list = []
        for item in values[:limit]:
            if isinstance(item, dict):
                clean: dict[str, Any] = {}
                for key, val in item.items():
                    if key.lower() in {"authorization", "cookie", "set-cookie", "token"}:
                        clean[key] = "[redacted]"
                    elif isinstance(val, str):
                        clean[key] = self._truncate(val, settings.SCANNER_STAGE_MESSAGE_MAX_LEN)
                    else:
                        clean[key] = val
                out.append(clean)
            elif isinstance(item, str):
                out.append(self._truncate(item, settings.SCANNER_STAGE_MESSAGE_MAX_LEN))
            else:
                out.append(item)
        return out

    def _build_stage_summary(
        self,
        stage_name: str,
        ctx: ScanContext,
        result: StageResult,
    ) -> tuple[dict, dict]:
        data = result.data if isinstance(result.data, dict) else {}
        preview_limit = max(1, int(settings.SCANNER_STAGE_PREVIEW_LIMIT))

        if stage_name == "recon":
            hosts = ctx.subdomains if isinstance(ctx.subdomains, list) else []
            dns_records = ctx.dns_records if isinstance(ctx.dns_records, list) else []
            summary = {
                "subdomains": len(hosts),
                "ip_hosts": len(ctx.ip_map or {}),
                "dns_records": len(dns_records),
                "whois_present": bool(ctx.whois),
                "zone_transfer_vulnerable": bool((data.get("recon_full") or {}).get("zone_transfer_vulnerable")),
            }
            preview = {"subdomains": self._safe_preview_list(hosts, preview_limit)}
            return summary, preview

        if stage_name == "network":
            services = ctx.services if isinstance(ctx.services, list) else []
            if not services and isinstance(data.get("services"), list):
                services = data.get("services") or []

            assets = ctx.assets if isinstance(ctx.assets, list) else []
            if not assets and isinstance(data.get("assets"), list):
                assets = data.get("assets") or []

            open_ports = sum(
                len((asset.get("open_ports") or []))
                for asset in assets
                if isinstance(asset, dict)
            )
            summary = {
                "ips_scanned": len({a.get("ip") for a in assets if isinstance(a, dict) and a.get("ip")}),
                "open_ports": open_ports,
                "services": len(services),
            }
            preview = {"services": self._safe_preview_list(services, preview_limit)}
            return summary, preview

        if stage_name == "os_fingerprint":
            fingerprints = ctx.os_fingerprints if isinstance(ctx.os_fingerprints, list) else []
            high_conf = sum(
                1 for f in fingerprints
                if isinstance(f, dict) and str(f.get("confidence", "")).lower() in {"high", "very_high"}
            )
            return {"fingerprints": len(fingerprints), "high_confidence": high_conf}, {
                "os_fingerprints": self._safe_preview_list(fingerprints, preview_limit),
            }

        if stage_name == "tls_engine":
            profiles = ctx.tls_profiles if isinstance(ctx.tls_profiles, list) else []
            tls13_hosts = 0
            weak_proto_hosts = 0
            for p in profiles:
                if not isinstance(p, dict):
                    continue
                versions = p.get("tls_versions_supported") or {}
                if isinstance(versions, dict) and versions.get("TLS_1_3"):
                    tls13_hosts += 1
                if isinstance(versions, dict) and (versions.get("TLS_1_0") or versions.get("TLS_1_1")):
                    weak_proto_hosts += 1
            return {
                "tls_profiles": len(profiles),
                "tls13_hosts": tls13_hosts,
                "weak_proto_hosts": weak_proto_hosts,
            }, {"tls_profiles": self._safe_preview_list(profiles, preview_limit)}

        if stage_name == "crypto_analysis":
            findings = ctx.crypto_findings if isinstance(ctx.crypto_findings, list) else []
            sev = {"critical": 0, "high": 0}
            hndl_hosts: set[str] = set()
            for f in findings:
                if not isinstance(f, dict):
                    continue
                risk = str(f.get("quantum_risk", "")).lower()
                if risk in sev:
                    sev[risk] += 1
                if f.get("hndl_risk") and f.get("host"):
                    hndl_hosts.add(str(f["host"]))
            return {
                "findings_total": len(findings),
                "critical": sev["critical"],
                "high": sev["high"],
                "hndl_hosts": len(hndl_hosts),
            }, {"crypto_findings": self._safe_preview_list(findings, preview_limit)}

        if stage_name == "cdn_waf":
            intel = ctx.cdn_waf_intel if isinstance(ctx.cdn_waf_intel, list) else []
            return {
                "cdn_hits": sum(1 for i in intel if isinstance(i, dict) and i.get("cdn_detected")),
                "waf_hits": sum(1 for i in intel if isinstance(i, dict) and i.get("waf_detected")),
                "proxy_hits": sum(1 for i in intel if isinstance(i, dict) and i.get("proxy_detected")),
            }, {"cdn_waf_intel": self._safe_preview_list(intel, preview_limit)}

        if stage_name == "tech_fingerprint":
            techs = ctx.tech_fingerprints if isinstance(ctx.tech_fingerprints, list) else []
            unique_tech = {
                str(t.get("technology", "")).lower()
                for t in techs if isinstance(t, dict) and t.get("technology")
            }
            return {
                "tech_hits": len(techs),
                "unique_tech": len(unique_tech),
            }, {"tech_fingerprints": self._safe_preview_list(techs, preview_limit)}

        if stage_name == "web_discovery":
            profiles = ctx.web_profiles if isinstance(ctx.web_profiles, list) else []
            api_endpoints = 0
            forms = 0
            for p in profiles:
                if not isinstance(p, dict):
                    continue
                api_endpoints += len(p.get("api_endpoints") or [])
                forms += len(p.get("forms") or [])
            return {
                "web_profiles": len(profiles),
                "api_endpoints": api_endpoints,
                "forms": forms,
            }, {"web_profiles": self._safe_preview_list(profiles, preview_limit)}

        if stage_name == "hidden_discovery":
            hidden = ctx.hidden_findings if isinstance(ctx.hidden_findings, list) else []
            return {
                "hidden_paths": len(hidden),
                "sensitive_files": sum(1 for h in hidden if isinstance(h, dict) and str(h.get("category", "")).lower() == "sensitive"),
                "admin_panels": sum(1 for h in hidden if isinstance(h, dict) and str(h.get("category", "")).lower() == "admin"),
            }, {"hidden_findings": self._safe_preview_list(hidden, preview_limit)}

        if stage_name == "vuln_engine":
            vulns = ctx.vuln_findings if isinstance(ctx.vuln_findings, list) else []
            cve_refs = sum(
                len(v.get("cve_ids") or [])
                for v in vulns if isinstance(v, dict)
            )
            return {
                "vulns_total": len(vulns),
                "critical": sum(1 for v in vulns if isinstance(v, dict) and str(v.get("severity", "")).lower() == "critical"),
                "high": sum(1 for v in vulns if isinstance(v, dict) and str(v.get("severity", "")).lower() == "high"),
                "cve_refs": cve_refs,
            }, {"vuln_findings": self._safe_preview_list(vulns, preview_limit)}

        if stage_name == "correlation":
            graph = ctx.graph if isinstance(ctx.graph, dict) else {}
            return {
                "graph_nodes": len(graph.get("nodes") or []),
                "graph_edges": len(graph.get("edges") or []),
                "attack_paths": len(graph.get("attack_paths") or []),
                "scored_assets": len(ctx.risk_scores or []),
            }, {"risk_scores": self._safe_preview_list(ctx.risk_scores, preview_limit)}

        if stage_name == "reporting":
            cbom_components = len((ctx.cbom or {}).get("components") or [])
            return {
                "cbom_components": cbom_components,
                "recommendations": len(ctx.recommendations or []),
                "executive_summary_present": bool(ctx.executive_summary),
                "quantum_score_present": bool(ctx.quantum_score),
            }, {
                "recommendations": self._safe_preview_list(ctx.recommendations, preview_limit),
            }

        fallback_summary = {
            "status": result.status,
            "request_count": result.request_count,
            "data_keys": len(data.keys()),
        }
        fallback_preview = {
            "data_keys": self._safe_preview_list(list(data.keys()), preview_limit),
        }
        return fallback_summary, fallback_preview
