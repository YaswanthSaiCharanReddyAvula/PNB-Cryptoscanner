"""
QuantumShield — Retry & Circuit Breaker

Provides exponential-backoff retry with jitter and per-stage circuit breakers
to prevent hammering unhealthy targets.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import TYPE_CHECKING

from app.scanner.models import StageResult
from app.utils.logger import get_logger

if TYPE_CHECKING:
    from app.scanner.pipeline import ScanContext, ScanStage

logger = get_logger(__name__)


class CircuitBreaker:
    """Three-state breaker: closed -> open -> half_open -> closed."""

    def __init__(self, failure_threshold: int = 3, recovery_timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state: str = "closed"
        self.failure_count: int = 0
        self.last_failure_time: float = 0.0

    def record_success(self) -> None:
        self.state = "closed"
        self.failure_count = 0

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "open"
            logger.warning(
                "Circuit breaker OPEN after %d failures", self.failure_count,
            )

    def should_allow(self) -> bool:
        if self.state == "closed":
            return True
        if self.state == "open":
            elapsed = time.time() - self.last_failure_time
            if elapsed >= self.recovery_timeout:
                self.state = "half_open"
                logger.info("Circuit breaker moved to HALF_OPEN after %.1fs", elapsed)
                return True
            return False
        # half_open — allow one probe request
        return True


class RetryManager:
    """Wraps stage execution with retries, backoff, and circuit breakers."""

    def __init__(self) -> None:
        self._breakers: dict[str, CircuitBreaker] = {}

    def _get_breaker(self, name: str) -> CircuitBreaker:
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker()
        return self._breakers[name]

    async def execute(
        self,
        stage: ScanStage,
        ctx: ScanContext,
        *,
        max_retries: int = 1,
    ) -> StageResult:
        breaker = self._get_breaker(stage.name)
        attempts = max(1, int(max_retries))

        if not breaker.should_allow():
            logger.warning(
                "Circuit breaker OPEN for stage %s — skipping execution",
                stage.name,
            )
            return StageResult(
                status="error",
                error=f"circuit breaker open for {stage.name}",
            )

        last_error: str | None = None

        for attempt in range(attempts):
            try:
                result = await stage.execute(ctx)
                breaker.record_success()
                return result

            except Exception as exc:
                last_error = str(exc)
                breaker.record_failure()
                logger.warning(
                    "Stage %s attempt %d/%d failed: %s",
                    stage.name, attempt + 1, attempts, exc,
                )

            if attempt < attempts - 1:
                base_delay = 2 ** attempt
                jitter = random.uniform(0, base_delay * 0.5)
                await asyncio.sleep(base_delay + jitter)

        return StageResult(status="error", error=last_error)
