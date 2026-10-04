"""
QuantumShield — SCA Core Models

Defines the canonical data structures for the Software Composition Analysis
subsystem: projects, packages, dependencies, findings, and vulnerability
intelligence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────

class ResolutionStatus(str, Enum):
    RESOLVED = "RESOLVED"
    PARTIALLY_RESOLVED = "PARTIALLY_RESOLVED"
    UNRESOLVED = "UNRESOLVED"
    UNKNOWN = "UNKNOWN"


class DependencyType(str, Enum):
    DIRECT = "DIRECT"
    TRANSITIVE = "TRANSITIVE"


class DependencyScope(str, Enum):
    RUNTIME = "RUNTIME"
    DEV = "DEV"
    TEST = "TEST"
    OPTIONAL = "OPTIONAL"
    BUILD = "BUILD"
    UNKNOWN = "UNKNOWN"


class VulnerabilityStatus(str, Enum):
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    POTENTIALLY_VULNERABLE = "POTENTIALLY_VULNERABLE"
    UNKNOWN = "UNKNOWN"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Ecosystem(str, Enum):
    PYPI = "pypi"
    NPM = "npm"
    MAVEN = "maven"
    GO = "go"
    CARGO = "cargo"
    NUGET = "nuget"
    COMPOSER = "composer"
    RUBYGEMS = "rubygems"
    UNKNOWN = "unknown"


# ── Package Identity ──────────────────────────────────────────────────

class PackageIdentity(BaseModel):
    """Canonical package identity using PURL as primary key."""
    ecosystem: Ecosystem
    namespace: Optional[str] = None
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None

    @property
    def display_name(self) -> str:
        if self.namespace:
            return f"{self.namespace}/{self.name}"
        return self.name


# ── Project ───────────────────────────────────────────────────────────

class SCAProject(BaseModel):
    """A logical project within a repository (e.g. a service in a monorepo)."""
    project_id: str = ""
    project_path: str = ""          # relative path within repository
    ecosystem: Ecosystem = Ecosystem.UNKNOWN
    manifest_files: List[str] = Field(default_factory=list)
    lockfile_files: List[str] = Field(default_factory=list)


# ── Dependency ────────────────────────────────────────────────────────

class SCADependency(BaseModel):
    """A resolved dependency with full lineage."""
    package: PackageIdentity
    declared_requirement: Optional[str] = None   # e.g. ">=41,<43"
    resolved_version: Optional[str] = None       # e.g. "42.0.8"
    resolution_status: ResolutionStatus = ResolutionStatus.UNKNOWN
    resolution_source: Optional[str] = None      # e.g. "poetry.lock"
    dependency_type: DependencyType = DependencyType.DIRECT
    scope: DependencyScope = DependencyScope.UNKNOWN
    parent: Optional[str] = None                 # PURL of parent
    dependency_path: List[str] = Field(default_factory=list)
    project_id: Optional[str] = None


# ── Vulnerability ─────────────────────────────────────────────────────

class CVSSInfo(BaseModel):
    """Normalized CVSS data."""
    version: Optional[str] = None    # "3.1", "2.0"
    base_score: Optional[float] = None
    vector: Optional[str] = None
    severity: Optional[str] = None   # CRITICAL/HIGH/MEDIUM/LOW


class VulnerabilityRecord(BaseModel):
    """A single advisory record from any feed."""
    vulnerability_id: str            # e.g. "CVE-2024-26130"
    aliases: List[str] = Field(default_factory=list)
    summary: str = ""
    details: str = ""
    ecosystem: Optional[str] = None
    package_name: Optional[str] = None
    affected_ranges: List[Dict[str, Any]] = Field(default_factory=list)
    fixed_versions: List[str] = Field(default_factory=list)
    cvss: Optional[CVSSInfo] = None
    cwe: List[str] = Field(default_factory=list)
    severity: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    known_exploited: Optional[bool] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    published: Optional[str] = None
    modified: Optional[str] = None
    source: str = ""                 # "osv", "nvd", "crypto_vuln_db"
    withdrawn: Optional[str] = None


# ── SCA Finding ───────────────────────────────────────────────────────

class SCAFindingV2(BaseModel):
    """Evidence-backed SCA finding correlating a dependency with a vulnerability."""
    finding_id: str = ""
    scan_id: str = ""

    # Package
    package: PackageIdentity
    resolved_version: Optional[str] = None
    declared_requirement: Optional[str] = None
    resolution_status: ResolutionStatus = ResolutionStatus.UNKNOWN

    # Dependency context
    dependency_type: DependencyType = DependencyType.DIRECT
    scope: DependencyScope = DependencyScope.UNKNOWN
    dependency_path: List[str] = Field(default_factory=list)

    # Vulnerability
    vulnerability_id: Optional[str] = None
    aliases: List[str] = Field(default_factory=list)
    vulnerability_status: VulnerabilityStatus = VulnerabilityStatus.UNKNOWN
    affected_range: Optional[str] = None
    fixed_versions: List[str] = Field(default_factory=list)
    cvss: Optional[CVSSInfo] = None
    cwe: List[str] = Field(default_factory=list)
    severity: Optional[str] = None
    known_exploited: Optional[bool] = None
    epss_score: Optional[float] = None

    # Evidence
    manifest_file: Optional[str] = None
    lockfile_file: Optional[str] = None
    project_id: Optional[str] = None

    # Crypto relevance (QuantumShield-specific)
    crypto_relevance: Optional[str] = None
    crypto_primitives: List[str] = Field(default_factory=list)
    pqc_relevance: Optional[str] = None

    # Metadata
    confidence: Confidence = Confidence.UNKNOWN
    vulnerability_source: Optional[str] = None
    observed_at: Optional[str] = None


# ── Database status ───────────────────────────────────────────────────

class VulnDBStatus(BaseModel):
    """Status of the local vulnerability database."""
    status: str = "UNKNOWN"     # FRESH | STALE | MISSING | CORRUPTED | SYNCING
    last_sync: Optional[str] = None
    record_count: int = 0
    source: Optional[str] = None
    schema_version: Optional[str] = None
