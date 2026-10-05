"""
QuantumShield — Container & Filesystem Common Inspection Models

Defines the normalized domain models for static container and filesystem inspection.
Strictly decoupled from execution runtimes and risk assignment engines.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class TargetType(str, Enum):
    CONTAINER_ARCHIVE = "container_archive"
    CONTAINER_IMAGE = "container_image"
    FILESYSTEM = "filesystem"
    REPOSITORY = "repository"
    EXTRACTED_IMAGE = "extracted_image"


class ArtifactType(str, Enum):
    CERTIFICATE = "certificate"
    CERTIFICATE_CHAIN = "certificate_chain"
    PRIVATE_KEY = "private_key"
    PUBLIC_KEY = "public_key"
    KEYSTORE = "keystore"
    TRUST_STORE = "trust_store"
    CRYPTO_CONFIG = "crypto_config"
    CRYPTO_LIBRARY = "crypto_library"
    CRYPTO_PACKAGE = "crypto_package"
    CRYPTO_PQC = "crypto_pqc"
    CRYPTO_SECRET = "crypto_secret"
    CRYPTO_ENV_VAR = "crypto_env_var"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class PQCClassification(str, Enum):
    PQC_CAPABLE_LIBRARY = "PQC_CAPABLE_LIBRARY"
    PQC_CONFIGURED = "PQC_CONFIGURED"
    PQC_USAGE_OBSERVED = "PQC_USAGE_OBSERVED"
    CLASSICAL = "CLASSICAL"
    HYBRID = "HYBRID"


class TargetAuthorization(BaseModel):
    """Scope authorization for inspection targets."""
    is_authorized: bool = True
    authorized_by: str = "scan_policy"
    scope_root: str
    allowed_paths: list[str] = Field(default_factory=list)
    denied_paths: list[str] = Field(default_factory=list)


class InspectionTarget(BaseModel):
    """Common inspection target for container images, archives, and host filesystems."""
    target_id: str = Field(default_factory=lambda: f"tgt-{uuid.uuid4().hex[:8]}")
    target_type: TargetType
    source_uri: str
    scope_root: str
    authorization: TargetAuthorization
    metadata: dict[str, Any] = Field(default_factory=dict)


class ResourceLimits(BaseModel):
    """Configurable boundaries to prevent zip bombs, tar bombs, and exhaustion."""
    max_image_size_bytes: int = 2 * 1024 * 1024 * 1024  # 2 GB
    max_layer_size_bytes: int = 1024 * 1024 * 1024       # 1 GB
    max_archive_size_bytes: int = 1024 * 1024 * 1024     # 1 GB
    max_extracted_size_bytes: int = 3 * 1024 * 1024 * 1024 # 3 GB
    max_file_count: int = 50_000
    max_file_size_bytes: int = 50 * 1024 * 1024          # 50 MB per file
    max_directory_depth: int = 30
    max_symlink_count: int = 5_000
    max_scan_time_seconds: int = 300
    max_total_bytes_read: int = 2 * 1024 * 1024 * 1024
    max_compression_ratio: float = 20.0


class FileArtifact(BaseModel):
    """Metadata for a statically discovered file."""
    file_path: str
    relative_path: str
    size_bytes: int
    file_type: str = "unknown"
    is_symlink: bool = False
    symlink_target: Optional[str] = None
    permissions_mode: Optional[int] = None
    is_world_readable: bool = False
    is_world_writable: bool = False
    sha256: Optional[str] = None
    layer_digest: Optional[str] = None
    layer_index: Optional[int] = None


class ContainerLayer(BaseModel):
    """One immutable layer of a container image."""
    layer_index: int
    layer_digest: str
    layer_tar_path: Optional[str] = None
    size_bytes: int = 0
    introduced_files: list[str] = Field(default_factory=list)
    modified_files: list[str] = Field(default_factory=list)
    deleted_files: list[str] = Field(default_factory=list)
    whiteout_files: list[str] = Field(default_factory=list)
    opaque_whiteout_dirs: list[str] = Field(default_factory=list)


class ContainerImageMetadata(BaseModel):
    """Statically extracted image manifest and configuration."""
    image_digest: str  # sha256:...
    repository: Optional[str] = None
    tag: Optional[str] = None
    identity_confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    architecture: Optional[str] = None
    os: Optional[str] = None
    created_at: Optional[str] = None
    config: dict[str, Any] = Field(default_factory=dict)
    entrypoint: list[str] = Field(default_factory=list)
    cmd: list[str] = Field(default_factory=list)
    env_vars: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    working_dir: Optional[str] = None
    user: Optional[str] = None
    is_root_user: bool = False
    layers: list[ContainerLayer] = Field(default_factory=list)


class CryptoObservation(BaseModel):
    """Normalized evidence schema for every discovered cryptographic artifact."""
    observation_id: str = Field(default_factory=lambda: f"obs-{uuid.uuid4().hex[:12]}")
    target_id: str
    target_type: str
    image_digest: Optional[str] = None
    layer_index: Optional[int] = None
    layer_digest: Optional[str] = None
    file_path: str
    artifact_type: str
    algorithm: str
    key_size: Optional[int] = None
    curve: Optional[str] = None
    signature_algorithm: Optional[str] = None
    fingerprint: Optional[str] = None
    pqc_classification: str = PQCClassification.CLASSICAL.value
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    parser: str = "unknown"
    evidence: dict[str, Any] = Field(default_factory=dict)
    final_image_presence: bool = True
    historical_layer_presence: bool = False
    observed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PackageObservation(BaseModel):
    """Statically discovered OS or language package metadata."""
    ecosystem: str  # dpkg | apk | rpm | pypi | npm | maven | go | rust
    name: str
    version: Optional[str] = None
    license: Optional[str] = None
    is_crypto_relevant: bool = False
    crypto_primitives: list[str] = Field(default_factory=list)
    pqc_support: list[str] = Field(default_factory=list)
    source_file: str
    version_source: str = "manifest"
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH


class InspectionResult(BaseModel):
    """Structured result returned by the InspectionCoordinator."""
    scan_metadata: dict[str, Any] = Field(default_factory=dict)
    target_metadata: dict[str, Any] = Field(default_factory=dict)
    files_inspected: int = 0
    files_skipped: int = 0
    artifacts_discovered: int = 0
    crypto_observations: list[CryptoObservation] = Field(default_factory=list)
    packages_discovered: list[PackageObservation] = Field(default_factory=list)
    certificates: list[dict[str, Any]] = Field(default_factory=list)
    keys: list[dict[str, Any]] = Field(default_factory=list)
    configs: list[dict[str, Any]] = Field(default_factory=list)
    libraries: list[dict[str, Any]] = Field(default_factory=list)
    pqc_observations: list[dict[str, Any]] = Field(default_factory=list)
    parser_errors: list[dict[str, Any]] = Field(default_factory=list)
    resource_limit_events: list[str] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)
