"""
QuantumShield — Smart Priority Scheduler (Stage 18)

Host triage, early stopping, and confidence-based finding filtering.
Runs continuously as a governor wrapping the pipeline — not a sequential
stage.
"""

from __future__ import annotations

import time
from typing import Any

from app.scanner.models import FuzzConfig, HostPriority, StageResult
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Severity ordering for confidence thresholds
CONFIDENCE_THRESHOLDS: dict[str, dict[str, float]] = {
    "aggressive": {
        "fuzz_finding":       0.40,
        "hidden_finding":     0.30,
        "behavioral_finding": 0.35,
        "dom_finding":        0.50,
        "vuln_finding":       0.45,
        "crypto_finding":     0.30,
    },
    "standard": {
        "fuzz_finding":       0.60,
        "hidden_finding":     0.50,
        "behavioral_finding": 0.55,
        "dom_finding":        0.65,
        "vuln_finding":       0.55,
        "crypto_finding":     0.40,
    },
    "fast": {
        "fuzz_finding":       0.80,
        "hidden_finding":     0.70,
        "behavioral_finding": 0.70,
        "dom_finding":        0.80,
        "vuln_finding":       0.70,
        "crypto_finding":     0.60,
    },
}

TIER_RANK = {"critical": 4, "high": 3, "standard": 2, "low": 1}

DB_PORTS = {3306, 5432, 6379, 27017, 1433, 9200, 11211, 5984}
REMOTE_PORTS = {22, 3389, 5900, 23}


class SmartScheduler:
    """Pipeline-level governor for host triage and budget enforcement."""

    def __init__(
        self,
        max_scan_seconds: int = 900,
        max_total_requests: int = 10000,
    ) -> None:
        self.max_scan_seconds = max_scan_seconds
        self.max_total_requests = max_total_requests
        self.start_time: float = 0.0
        self.request_count: int = 0
        self.host_priorities: dict[str, HostPriority] = {}

    def start(self) -> None:
        self.start_time = time.time()

    def should_continue(self) -> bool:
        if self.start_time and time.time() - self.start_time > self.max_scan_seconds:
            logger.info("Scheduler: time budget exhausted (%ds)", self.max_scan_seconds)
            return False
        if self.request_count > self.max_total_requests:
            logger.info("Scheduler: request budget exhausted (%d)", self.max_total_requests)
            return False
        return True

    def prioritize_hosts(
        self,
        assets: list[dict],
        services: list[dict],
        findings: list[dict],
    ) -> None:
        """Assign priority tiers after Stage 2 (Network)."""
        for asset in assets:
            host = asset.get("subdomain") or asset.get("host") or ""
            if not host:
                continue

            score = 0
            open_ports = asset.get("open_ports", [])

            if any(p in DB_PORTS for p in open_ports):
                score += 30
            if any(p in REMOTE_PORTS for p in open_ports):
                score += 20
            if any(p in (80, 443, 8080, 8443) for p in open_ports):
                score += 10
            if len(open_ports) > 10:
                score += 15

            host_findings = [f for f in findings if f.get("host") == host]
            score += len(host_findings) * 5

            crit = asset.get("criticality", "medium")
            score += {"critical": 30, "high": 20, "medium": 10, "low": 0}.get(crit, 10)

            tier = (
                "critical" if score >= 50
                else "high" if score >= 30
                else "standard" if score >= 15
                else "low"
            )

            self.host_priorities[host] = HostPriority(
                host=host,
                score=score,
                tier=tier,
                deep_scan=tier in ("critical", "high"),
                browser_scan=tier == "critical",
                fuzz_depth="full" if tier == "critical" else "light" if tier in ("high", "standard") else "skip",
            )

    def filter_by_tier(self, hosts: list[str], min_tier: str = "standard") -> list[str]:
        min_rank = TIER_RANK.get(min_tier, 2)
        return [
            h for h in hosts
            if TIER_RANK.get(
                (self.host_priorities.get(h) or HostPriority()).tier, 0
            ) >= min_rank
        ]

    def get_fuzz_config(self, host: str) -> FuzzConfig:
        pri = self.host_priorities.get(host, HostPriority())
        if pri.fuzz_depth == "full":
            return FuzzConfig(max_params=50, max_payloads=7, max_forms=20)
        if pri.fuzz_depth == "light":
            return FuzzConfig(max_params=10, max_payloads=3, max_forms=5)
        return FuzzConfig(max_params=0, max_payloads=0, max_forms=0)


class ConfidenceFilter:
    """Post-scan filter that removes low-confidence findings."""

    def filter(self, findings: list[dict], scan_depth: str = "standard") -> list[dict]:
        thresholds = CONFIDENCE_THRESHOLDS.get(scan_depth, CONFIDENCE_THRESHOLDS["standard"])
        filtered: list[dict] = []
        for f in findings:
            ftype = f.get("_finding_type", "vuln_finding")
            threshold = thresholds.get(ftype, 0.50)
            conf = f.get("confidence", 0)
            if isinstance(conf, (int, float)) and conf >= threshold:
                filtered.append(f)
            elif not isinstance(conf, (int, float)):
                filtered.append(f)
        return filtered
