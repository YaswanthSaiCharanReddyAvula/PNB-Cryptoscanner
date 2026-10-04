"""
QuantumShield — Manifest & Lockfile Discovery

Recursively discovers dependency manifests and lockfiles within a source
tree, respecting resource limits and skipping unsafe paths.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Well-known manifest/lockfile names ───────────────────────────────

MANIFEST_NAMES = frozenset({
    # Python
    "requirements.txt", "pyproject.toml", "pipfile", "setup.cfg",
    # Node.js
    "package.json",
    # Java
    "pom.xml",
    # Go
    "go.mod",
    # Rust
    "cargo.toml",
    # .NET
    "packages.config",
    # PHP
    "composer.json",
    # Ruby
    "gemfile",
})

LOCKFILE_NAMES = frozenset({
    # Python
    "poetry.lock", "pipfile.lock",
    # Node.js
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    # Go
    "go.sum",
    # Rust
    "cargo.lock",
    # .NET
    "packages.lock.json",
    # PHP
    "composer.lock",
    # Ruby
    "gemfile.lock",
})

# Also accept requirements files matching requirements*.txt
def _is_requirements_file(name: str) -> bool:
    lower = name.lower()
    return lower.startswith("requirements") and lower.endswith(".txt")

# Also accept .csproj files
def _is_csproj(name: str) -> bool:
    return name.lower().endswith(".csproj")


SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "target", ".tox", ".mypy_cache", ".pytest_cache",
    "site-packages", ".cache", ".idea", ".vscode", "vendor",
    "coverage", ".gradle", ".mvn",
})

# ── Resource Limits ──────────────────────────────────────────────────

MAX_DIRECTORY_DEPTH = 30
MAX_FILES_SCANNED = 50_000
MAX_MANIFEST_SIZE = 5 * 1024 * 1024   # 5 MB
MAX_LOCKFILE_SIZE = 50 * 1024 * 1024  # 50 MB


@dataclass
class DiscoveredManifest:
    file_path: str
    relative_path: str
    filename: str
    is_lockfile: bool
    ecosystem: str
    project_dir: str   # relative dir within root
    size: int = 0


@dataclass
class SkippedItem:
    path: str
    reason: str   # SKIPPED_RESOURCE_LIMIT | SKIPPED_PERMISSION | etc.
    detail: str = ""


@dataclass
class DiscoveryResult:
    manifests: List[DiscoveredManifest] = field(default_factory=list)
    lockfiles: List[DiscoveredManifest] = field(default_factory=list)
    skipped: List[SkippedItem] = field(default_factory=list)
    files_scanned: int = 0


def _classify_ecosystem(filename: str) -> str:
    lower = filename.lower()
    if lower in ("requirements.txt", "pyproject.toml", "pipfile", "setup.cfg",
                 "poetry.lock", "pipfile.lock") or _is_requirements_file(filename):
        return "pypi"
    if lower in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        return "npm"
    if lower == "pom.xml":
        return "maven"
    if lower in ("go.mod", "go.sum"):
        return "go"
    if lower in ("cargo.toml", "cargo.lock"):
        return "cargo"
    if lower in ("packages.config", "packages.lock.json") or _is_csproj(filename):
        return "nuget"
    if lower in ("composer.json", "composer.lock"):
        return "composer"
    if lower in ("gemfile", "gemfile.lock"):
        return "rubygems"
    return "unknown"


def discover_manifests(root_path: str, scope: str = "/") -> DiscoveryResult:
    """
    Recursively discover all dependency manifests and lockfiles.

    Returns a DiscoveryResult with manifests, lockfiles, and skipped items.
    """
    abs_root = os.path.abspath(root_path)
    scope_path = scope.lstrip("/")
    search_root = os.path.abspath(os.path.join(abs_root, scope_path))

    # Prevent traversal escape
    if not search_root.startswith(abs_root):
        return DiscoveryResult(
            skipped=[SkippedItem(scope, "SKIPPED_TRAVERSAL_ESCAPE")]
        )

    if not os.path.isdir(search_root):
        return DiscoveryResult(
            skipped=[SkippedItem(scope, "SKIPPED_NOT_DIRECTORY")]
        )

    result = DiscoveryResult()

    for dirpath, dirnames, filenames in os.walk(search_root, topdown=True, followlinks=False):
        # Depth check
        rel = os.path.relpath(dirpath, search_root)
        depth = 0 if rel == "." else len(rel.split(os.sep))
        if depth >= MAX_DIRECTORY_DEPTH:
            result.skipped.append(SkippedItem(
                os.path.relpath(dirpath, abs_root),
                "SKIPPED_RESOURCE_LIMIT",
                f"depth={depth} >= {MAX_DIRECTORY_DEPTH}"
            ))
            dirnames[:] = []
            continue

        # File count limit
        if result.files_scanned >= MAX_FILES_SCANNED:
            result.skipped.append(SkippedItem(
                os.path.relpath(dirpath, abs_root),
                "SKIPPED_RESOURCE_LIMIT",
                f"files_scanned={result.files_scanned} >= {MAX_FILES_SCANNED}"
            ))
            dirnames[:] = []
            continue

        # Skip excluded directories
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]

        for filename in filenames:
            result.files_scanned += 1
            filepath = os.path.join(dirpath, filename)
            lower = filename.lower()

            # Check if it's a manifest or lockfile
            is_lockfile = lower in LOCKFILE_NAMES
            is_manifest = (
                lower in MANIFEST_NAMES
                or _is_requirements_file(filename)
                or _is_csproj(filename)
            )

            if not is_manifest and not is_lockfile:
                continue

            # Symlink check
            if os.path.islink(filepath):
                result.skipped.append(SkippedItem(
                    os.path.relpath(filepath, abs_root),
                    "SKIPPED_SYMLINK"
                ))
                continue

            # Size check
            try:
                size = os.path.getsize(filepath)
            except OSError as e:
                result.skipped.append(SkippedItem(
                    os.path.relpath(filepath, abs_root),
                    "SKIPPED_PERMISSION",
                    str(e)
                ))
                continue

            max_size = MAX_LOCKFILE_SIZE if is_lockfile else MAX_MANIFEST_SIZE
            if size > max_size:
                result.skipped.append(SkippedItem(
                    os.path.relpath(filepath, abs_root),
                    "SKIPPED_RESOURCE_LIMIT",
                    f"size={size} > {max_size}"
                ))
                continue

            eco = _classify_ecosystem(filename)
            rel_path = os.path.relpath(filepath, abs_root)
            proj_dir = os.path.relpath(dirpath, abs_root)
            if proj_dir == ".":
                proj_dir = ""

            manifest = DiscoveredManifest(
                file_path=filepath,
                relative_path=rel_path,
                filename=filename,
                is_lockfile=is_lockfile,
                ecosystem=eco,
                project_dir=proj_dir,
                size=size,
            )

            if is_lockfile:
                result.lockfiles.append(manifest)
            else:
                result.manifests.append(manifest)

    logger.info(
        "SCA discovery: %d manifests, %d lockfiles, %d skipped, %d files scanned",
        len(result.manifests), len(result.lockfiles),
        len(result.skipped), result.files_scanned,
    )

    return result
