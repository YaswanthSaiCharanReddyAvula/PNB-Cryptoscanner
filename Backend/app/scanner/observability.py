"""
QuantumShield — Scan Observability

Collects structured per-stage metrics and emits JSON log lines for
real-time monitoring and post-scan analysis.
"""

from __future__ import annotations

import json
import time

from app.scanner.models import StageMetrics
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ScanObserver:
    """Collects structured metrics throughout the pipeline."""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.stage_metrics: list[StageMetrics] = []
        self.total_requests: int = 0
        self.total_errors: int = 0
        self.total_retries: int = 0
        self.start_time: float = time.time()

    def record_stage(self, metrics: StageMetrics) -> None:
        self.stage_metrics.append(metrics)
        self.total_requests += metrics.request_count
        if metrics.status in ("error", "timeout"):
            self.total_errors += 1
        logger.info(
            "stage_metric %s",
            json.dumps({
                "scan_id": self.scan_id,
                "stage": metrics.name,
                "status": metrics.status,
                "duration": round(metrics.duration, 3),
                "requests": metrics.request_count,
                "error": metrics.error,
            }),
        )

    def summary(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "total_duration": round(time.time() - self.start_time, 3),
            "total_requests": self.total_requests,
            "total_errors": self.total_errors,
            "stages": [m.model_dump() for m in self.stage_metrics],
        }
