"""
QuantumShield — npm/Yarn/pnpm Manifest & Lockfile Parsers

Supports: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
"""

from __future__ import annotations

import json
import re
from typing import List

from app.scanner.sca.models.package import (
    DependencyScope, DependencyType, Ecosystem,
    PackageIdentity, ResolutionStatus, SCADependency,
)
from app.scanner.sca.identity.purl import generate_purl
from app.utils.logger import get_logger

logger = get_logger(__name__)


def parse_package_json(filepath: str) -> List[SCADependency]:
    """Parse package.json preserving declared version ranges."""
    deps = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            pkg = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to parse %s: %s", filepath, e)
        return deps

    scope_map = {
        "dependencies": DependencyScope.RUNTIME,
        "devDependencies": DependencyScope.DEV,
        "optionalDependencies": DependencyScope.OPTIONAL,
        "peerDependencies": DependencyScope.RUNTIME,
    }

    for section, scope in scope_map.items():
        section_deps = pkg.get(section, {})
        if not isinstance(section_deps, dict):
            continue
        for name, ver_spec in section_deps.items():
            ver_spec = str(ver_spec) if ver_spec else ""
            # DO NOT strip range operators. Preserve declared requirement as-is.
            deps.append(SCADependency(
                package=PackageIdentity(
                    ecosystem=Ecosystem.NPM,
                    name=name,
                    purl=generate_purl(Ecosystem.NPM, name),
                ),
                declared_requirement=ver_spec or None,
                resolution_status=ResolutionStatus.UNRESOLVED,
                resolution_source=filepath,
                dependency_type=DependencyType.DIRECT,
                scope=scope,
            ))

    return deps


def parse_package_lock_json(filepath: str) -> List[SCADependency]:
    """Parse package-lock.json (v2/v3) for exact resolved versions with transitives."""
    deps = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to parse %s: %s", filepath, e)
        return deps

    lock_version = data.get("lockfileVersion", 1)

    if lock_version >= 2:
        # v2/v3: use "packages" key
        packages = data.get("packages", {})
        for pkg_path, info in packages.items():
            if not pkg_path:  # Root entry
                continue
            if not isinstance(info, dict):
                continue
            version = info.get("version")
            resolved = info.get("resolved", "")
            dev = info.get("dev", False)
            optional = info.get("optional", False)

            # Extract package name from path
            # node_modules/foo or node_modules/@scope/bar
            name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path

            scope = DependencyScope.DEV if dev else (
                DependencyScope.OPTIONAL if optional else DependencyScope.RUNTIME
            )

            # Determine if direct (top-level node_modules/foo, not nested)
            parts = pkg_path.split("node_modules/")
            is_direct = len(parts) <= 2 and parts[0] == ""

            purl = generate_purl(Ecosystem.NPM, name, version)

            deps.append(SCADependency(
                package=PackageIdentity(
                    ecosystem=Ecosystem.NPM,
                    name=name,
                    version=version,
                    purl=purl,
                ),
                resolved_version=version,
                resolution_status=(
                    ResolutionStatus.RESOLVED if version
                    else ResolutionStatus.UNKNOWN
                ),
                resolution_source=filepath,
                dependency_type=(
                    DependencyType.DIRECT if is_direct
                    else DependencyType.TRANSITIVE
                ),
                scope=scope,
            ))
    else:
        # v1: use "dependencies" key (recursive)
        _parse_lock_v1_deps(data.get("dependencies", {}), filepath, deps, is_direct=True)

    return deps


def _parse_lock_v1_deps(
    deps_obj: dict,
    filepath: str,
    result: List[SCADependency],
    is_direct: bool = True,
    parent_path: List[str] | None = None,
):
    """Recursively parse v1 lock dependencies."""
    if parent_path is None:
        parent_path = []

    for name, info in deps_obj.items():
        if not isinstance(info, dict):
            continue
        version = info.get("version")
        dev = info.get("dev", False)

        scope = DependencyScope.DEV if dev else DependencyScope.RUNTIME
        path = parent_path + [name]

        purl = generate_purl(Ecosystem.NPM, name, version)

        result.append(SCADependency(
            package=PackageIdentity(
                ecosystem=Ecosystem.NPM,
                name=name,
                version=version,
                purl=purl,
            ),
            resolved_version=version,
            resolution_status=(
                ResolutionStatus.RESOLVED if version
                else ResolutionStatus.UNKNOWN
            ),
            resolution_source=filepath,
            dependency_type=(
                DependencyType.DIRECT if is_direct
                else DependencyType.TRANSITIVE
            ),
            scope=scope,
            dependency_path=path,
        ))

        # Recurse into nested dependencies
        nested = info.get("dependencies", {})
        if nested:
            _parse_lock_v1_deps(nested, filepath, result, is_direct=False, parent_path=path)


def parse_yarn_lock(filepath: str) -> List[SCADependency]:
    """Parse yarn.lock (v1 format) for resolved versions."""
    deps = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError as e:
        logger.warning("Failed to read %s: %s", filepath, e)
        return deps

    # Match patterns like: "package@^1.0.0":\n  version "1.0.5"
    block_pattern = re.compile(
        r'^"?([^@\s]+)@[^"]*"?:\s*\n\s+version\s+"([^"]+)"',
        re.MULTILINE,
    )

    for m in block_pattern.finditer(content):
        name = m.group(1)
        version = m.group(2)

        purl = generate_purl(Ecosystem.NPM, name, version)

        deps.append(SCADependency(
            package=PackageIdentity(
                ecosystem=Ecosystem.NPM,
                name=name,
                version=version,
                purl=purl,
            ),
            resolved_version=version,
            resolution_status=ResolutionStatus.RESOLVED,
            resolution_source=filepath,
            dependency_type=DependencyType.DIRECT,  # Will be reclassified
            scope=DependencyScope.UNKNOWN,
        ))

    return deps
