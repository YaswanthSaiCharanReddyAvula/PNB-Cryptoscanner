"""
QuantumShield — Java/Maven & Go Manifest & Lockfile Parsers

Supports: pom.xml, go.mod, go.sum
"""

from __future__ import annotations

import re
from xml.etree import ElementTree
from typing import List

from app.scanner.sca.models.package import (
    DependencyScope, DependencyType, Ecosystem,
    PackageIdentity, ResolutionStatus, SCADependency,
)
from app.scanner.sca.identity.purl import generate_purl
from app.utils.logger import get_logger

logger = get_logger(__name__)


def parse_pom_xml(filepath: str) -> List[SCADependency]:
    """Parse pom.xml extracting groupId:artifactId and version."""
    deps = []
    try:
        tree = ElementTree.parse(filepath)
        root = tree.getroot()

        # Handle namespaces like {http://maven.apache.org/POM/4.0.0}dependency
        for dep in root.iter():
            tag = dep.tag.split("}")[-1] if "}" in dep.tag else dep.tag
            if tag != "dependency":
                continue

            group_id = ""
            artifact_id = ""
            version = None
            scope_str = "compile"

            for child in dep:
                child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child_tag == "groupId":
                    group_id = (child.text or "").strip()
                elif child_tag == "artifactId":
                    artifact_id = (child.text or "").strip()
                elif child_tag == "version":
                    version = (child.text or "").strip()
                elif child_tag == "scope":
                    scope_str = (child.text or "").strip()

            if not artifact_id:
                continue

            # Maven resolves properties like ${foo.version}. We don't interpolate perfectly,
            # so if it's a variable, mark unresolved.
            is_var = version and version.startswith("${")

            name = f"{group_id}:{artifact_id}" if group_id else artifact_id

            scope_map = {
                "compile": DependencyScope.RUNTIME,
                "provided": DependencyScope.RUNTIME,
                "runtime": DependencyScope.RUNTIME,
                "test": DependencyScope.TEST,
                "system": DependencyScope.RUNTIME,
                "import": DependencyScope.UNKNOWN,
            }
            scope = scope_map.get(scope_str, DependencyScope.UNKNOWN)

            purl = generate_purl(Ecosystem.MAVEN, artifact_id, version if not is_var else None, namespace=group_id or None)

            deps.append(SCADependency(
                package=PackageIdentity(
                    ecosystem=Ecosystem.MAVEN,
                    namespace=group_id or None,
                    name=artifact_id,
                    version=version if not is_var else None,
                    purl=purl,
                ),
                declared_requirement=version,
                resolved_version=version if not is_var else None,
                resolution_status=(
                    ResolutionStatus.RESOLVED if version and not is_var
                    else ResolutionStatus.UNRESOLVED
                ),
                resolution_source=filepath,
                dependency_type=DependencyType.DIRECT,
                scope=scope,
            ))
    except (ElementTree.ParseError, OSError) as e:
        logger.warning("Failed to parse %s: %s", filepath, e)

    return deps


def parse_go_mod(filepath: str) -> List[SCADependency]:
    """Parse go.mod for require directives."""
    deps = []
    require_pattern = re.compile(r"^\s*([a-zA-Z0-9_./-]+)\s+v?([0-9][0-9.a-zA-Z\-]*(?:\+incompatible)?)(?:\s+//\s*(indirect))?")

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            in_require = False
            for line in f:
                stripped = line.strip()
                if stripped.startswith("require"):
                    in_require = True
                    # Single-line require
                    if "(" not in stripped and ")" not in stripped:
                        in_require = False
                    # Fallthrough to match just in case it's single line like `require foo v1`
                if stripped == ")" and in_require:
                    in_require = False
                    continue
                
                if in_require or stripped.startswith("require "):
                    m = require_pattern.search(stripped)
                    if m:
                        mod = m.group(1)
                        version = m.group(2)
                        indirect = bool(m.group(3))

                        purl = generate_purl(Ecosystem.GO, mod, version)

                        deps.append(SCADependency(
                            package=PackageIdentity(
                                ecosystem=Ecosystem.GO,
                                name=mod,
                                version=version,
                                purl=purl,
                            ),
                            declared_requirement=version,
                            resolution_status=ResolutionStatus.RESOLVED, # go.mod contains resolved versions usually
                            resolution_source=filepath,
                            dependency_type=(
                                DependencyType.TRANSITIVE if indirect else DependencyType.DIRECT
                            ),
                            scope=DependencyScope.RUNTIME,
                        ))
    except OSError as e:
        logger.warning("Failed to read %s: %s", filepath, e)

    return deps


def parse_go_sum(filepath: str) -> List[SCADependency]:
    """Parse go.sum for exact resolved versions."""
    deps = []
    # format: module version h1:hash
    # or: module version/go.mod h1:hash
    pattern = re.compile(r"^([a-zA-Z0-9_./-]+)\s+v?([0-9][0-9.a-zA-Z\-]*(?:\+incompatible)?)(?:/go\.mod)?\s+h1:")

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    mod = m.group(1)
                    version = m.group(2)
                    
                    purl = generate_purl(Ecosystem.GO, mod, version)

                    deps.append(SCADependency(
                        package=PackageIdentity(
                            ecosystem=Ecosystem.GO,
                            name=mod,
                            version=version,
                            purl=purl,
                        ),
                        resolved_version=version,
                        resolution_status=ResolutionStatus.RESOLVED,
                        resolution_source=filepath,
                        dependency_type=DependencyType.DIRECT, # Reclassified by graph
                        scope=DependencyScope.RUNTIME,
                    ))
    except OSError as e:
        logger.warning("Failed to read %s: %s", filepath, e)

    return deps
