"""
QuantumShield — Python Manifest & Lockfile Parsers

Supports: requirements.txt, pyproject.toml, Pipfile, poetry.lock, Pipfile.lock
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from app.scanner.sca.models.package import (
    DependencyScope, DependencyType, Ecosystem,
    PackageIdentity, ResolutionStatus, SCADependency,
)
from app.scanner.sca.identity.purl import generate_purl, normalize_package_name
from app.utils.logger import get_logger

logger = get_logger(__name__)


def parse_requirements_txt(filepath: str) -> List[SCADependency]:
    """Parse requirements.txt preserving declared ranges without converting to versions."""
    deps = []
    req_pattern = re.compile(
        r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*?)(?:\s*;.*)?(?:\s*#.*)?$"
    )

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = req_pattern.match(line)
                if not m:
                    continue
                raw_name = m.group(1)
                version_spec = m.group(2).strip()

                name = normalize_package_name(Ecosystem.PYPI, raw_name)
                # Extract exact version if pinned (==X.Y.Z)
                exact = re.match(r"^==\s*([0-9][0-9.a-zA-Z]*)", version_spec)

                purl = generate_purl(Ecosystem.PYPI, name, exact.group(1) if exact else None)

                deps.append(SCADependency(
                    package=PackageIdentity(
                        ecosystem=Ecosystem.PYPI,
                        name=name,
                        version=exact.group(1) if exact else None,
                        purl=purl,
                    ),
                    declared_requirement=version_spec or None,
                    resolved_version=exact.group(1) if exact else None,
                    resolution_status=(
                        ResolutionStatus.RESOLVED if exact
                        else ResolutionStatus.UNRESOLVED
                    ),
                    resolution_source=filepath,
                    dependency_type=DependencyType.DIRECT,
                    scope=DependencyScope.UNKNOWN,
                ))
    except OSError as e:
        logger.warning("Failed to parse %s: %s", filepath, e)

    return deps


def parse_pyproject_toml(filepath: str) -> List[SCADependency]:
    """Parse pyproject.toml for [project.dependencies] and [tool.poetry.dependencies]."""
    deps = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError as e:
        logger.warning("Failed to read %s: %s", filepath, e)
        return deps

    # Extract dependency strings from common patterns
    dep_strings = re.findall(r'"([A-Za-z0-9][A-Za-z0-9._-]*(?:\s*[><=!~^][^"]*)?)"', content)

    dep_pattern = re.compile(r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)')
    for ds in dep_strings:
        m = dep_pattern.match(ds.strip())
        if not m:
            continue
        raw_name = m.group(1)
        spec = m.group(2).strip()

        name = normalize_package_name(Ecosystem.PYPI, raw_name)
        exact = re.match(r'^==\s*([0-9][0-9.a-zA-Z]*)', spec)

        deps.append(SCADependency(
            package=PackageIdentity(
                ecosystem=Ecosystem.PYPI,
                name=name,
                version=exact.group(1) if exact else None,
                purl=generate_purl(Ecosystem.PYPI, name, exact.group(1) if exact else None),
            ),
            declared_requirement=spec or None,
            resolved_version=exact.group(1) if exact else None,
            resolution_status=(
                ResolutionStatus.RESOLVED if exact
                else ResolutionStatus.UNRESOLVED
            ),
            resolution_source=filepath,
            dependency_type=DependencyType.DIRECT,
            scope=DependencyScope.UNKNOWN,
        ))

    return deps


def parse_pipfile(filepath: str) -> List[SCADependency]:
    """Parse Pipfile for [packages] and [dev-packages]."""
    deps = []
    in_packages = False
    current_scope = DependencyScope.UNKNOWN
    pkg_pattern = re.compile(r'^([A-Za-z0-9_-]+)\s*=\s*"?([^"]*)"?')

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                stripped = line.strip()
                if stripped == "[packages]":
                    in_packages = True
                    current_scope = DependencyScope.RUNTIME
                    continue
                elif stripped == "[dev-packages]":
                    in_packages = True
                    current_scope = DependencyScope.DEV
                    continue
                elif stripped.startswith("[") and in_packages:
                    in_packages = False
                    continue

                if in_packages:
                    m = pkg_pattern.match(stripped)
                    if m:
                        raw_name = m.group(1)
                        spec = m.group(2).strip()
                        if spec.startswith("{"):
                            spec = None  # Complex TOML spec

                        name = normalize_package_name(Ecosystem.PYPI, raw_name)

                        deps.append(SCADependency(
                            package=PackageIdentity(
                                ecosystem=Ecosystem.PYPI,
                                name=name,
                                purl=generate_purl(Ecosystem.PYPI, name),
                            ),
                            declared_requirement=spec,
                            resolution_status=ResolutionStatus.UNRESOLVED,
                            resolution_source=filepath,
                            dependency_type=DependencyType.DIRECT,
                            scope=current_scope,
                        ))
    except OSError as e:
        logger.warning("Failed to parse %s: %s", filepath, e)

    return deps


def parse_poetry_lock(filepath: str) -> List[SCADependency]:
    """Parse poetry.lock for resolved packages with transitive information."""
    deps = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError as e:
        logger.warning("Failed to read %s: %s", filepath, e)
        return deps

    # poetry.lock is TOML with [[package]] sections
    package_blocks = re.split(r'\[\[package\]\]', content)
    for block in package_blocks[1:]:  # Skip preamble
        name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
        ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
        cat_m = re.search(r'category\s*=\s*"([^"]+)"', block)
        opt_m = re.search(r'optional\s*=\s*(true|false)', block)

        if not name_m or not ver_m:
            continue

        raw_name = name_m.group(1)
        version = ver_m.group(1)
        category = cat_m.group(1) if cat_m else "main"

        name = normalize_package_name(Ecosystem.PYPI, raw_name)
        scope = DependencyScope.DEV if category == "dev" else DependencyScope.RUNTIME

        purl = generate_purl(Ecosystem.PYPI, name, version)

        # Check for [package.dependencies] to build graph later
        has_deps = "[package.dependencies]" in block

        deps.append(SCADependency(
            package=PackageIdentity(
                ecosystem=Ecosystem.PYPI,
                name=name,
                version=version,
                purl=purl,
            ),
            resolved_version=version,
            resolution_status=ResolutionStatus.RESOLVED,
            resolution_source=filepath,
            dependency_type=DependencyType.DIRECT,  # Will be reclassified by graph builder
            scope=scope,
        ))

    return deps


def parse_pipfile_lock(filepath: str) -> List[SCADependency]:
    """Parse Pipfile.lock JSON for exact resolved versions."""
    deps = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to parse %s: %s", filepath, e)
        return deps

    for section in ("default", "develop"):
        section_data = data.get(section, {})
        scope = DependencyScope.DEV if section == "develop" else DependencyScope.RUNTIME

        for raw_name, info in section_data.items():
            if not isinstance(info, dict):
                continue
            version_str = info.get("version", "")
            version = version_str.lstrip("=").strip() if version_str else None

            name = normalize_package_name(Ecosystem.PYPI, raw_name)
            purl = generate_purl(Ecosystem.PYPI, name, version)

            deps.append(SCADependency(
                package=PackageIdentity(
                    ecosystem=Ecosystem.PYPI,
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
                dependency_type=DependencyType.DIRECT,  # Reclassified by graph
                scope=scope,
            ))

    return deps
