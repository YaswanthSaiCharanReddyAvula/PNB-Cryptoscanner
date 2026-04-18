"""
QuantumShield — Throttle Controller

Two-layer async semaphore system: a global concurrency cap plus per-category
limits to prevent overwhelming specific network subsystems.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

from app.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_CATEGORY_LIMITS: dict[str, int] = {
    "dns": 50,
    "tcp_scan": 200,
    "tls_probe": 10,
    "http_probe": 20,
    "path_fuzz": 20,
    "crawl": 5,
    "fuzz": 3,
    "browser": 2,
}


class ThrottleController:
    """Global + per-category async semaphore throttle."""

    def __init__(
        self,
        global_limit: int = 500,
        category_limits: dict[str, int] | None = None,
    ):
        self._global = asyncio.Semaphore(global_limit)
        limits = category_limits or DEFAULT_CATEGORY_LIMITS
        self._categories: dict[str, asyncio.Semaphore] = {
            cat: asyncio.Semaphore(cap) for cat, cap in limits.items()
        }

    @asynccontextmanager
    async def acquire(self, category: str) -> AsyncIterator[None]:
        cat_sem = self._categories.get(category)
        if cat_sem is None:
            cat_sem = asyncio.Semaphore(10)
            self._categories[category] = cat_sem
            logger.debug("Created default semaphore (10) for category %s", category)

        async with self._global:
            async with cat_sem:
                yield
