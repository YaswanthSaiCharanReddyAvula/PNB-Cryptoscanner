"""
QuantumShield — Centralized Logging

Provides a module-level logger factory with structured formatting.
"""

import logging
import sys
from app.config import settings


def get_logger(name: str) -> logging.Logger:
    """
    Create and return a logger with a consistent format.

    Args:
        name: Typically __name__ of the calling module.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
    logger.propagate = False  # prevent duplicate output to root logger
    return logger
