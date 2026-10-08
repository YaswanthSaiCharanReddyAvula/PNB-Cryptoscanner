"""
QuantumShield — Convergence Enums

Defines the normalized enums used across the canonical data models.
"""

from enum import Enum


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class ObservationStatus(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    DERIVED = "DERIVED"
    ENRICHED = "ENRICHED"
    NOT_OBSERVED = "NOT_OBSERVED"
    NOT_SCANNED = "NOT_SCANNED"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"
    REDACTED = "REDACTED"


class AssetType(str, Enum):
    APPLICATION = "application"
    SERVICE = "service"
    LIBRARY = "library"
    PACKAGE = "package"
    FRAMEWORK = "framework"
    CONTAINER = "container"
    HOST = "host"
    CERTIFICATE = "certificate"
    KEY = "key"
    ALGORITHM = "algorithm"
    PROTOCOL = "protocol"
    CLOUD_RESOURCE = "cloud_resource"
    CRYPTOGRAPHIC_ASSET = "cryptographic_asset"
