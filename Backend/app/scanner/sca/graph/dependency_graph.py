"""
QuantumShield — Dependency Graph

Unifies manifests and lockfiles into a coherent dependency graph.
"""

from __future__ import annotations

from typing import Dict, List, Set

from app.scanner.sca.models.package import (
    DependencyType, ResolutionStatus, SCADependency, SCAProject,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


class DependencyGraphBuilder:
    """Builds a normalized dependency graph per project."""

    def __init__(self):
        # purl -> SCADependency (or normalized package string if purl missing)
        self.inventory: Dict[str, SCADependency] = {}
        self.direct_purls: Set[str] = set()

    def add_manifest_dependencies(self, deps: List[SCADependency]):
        """Add dependencies declared in a manifest (typically direct)."""
        for dep in deps:
            key = dep.package.purl or dep.package.display_name
            if key not in self.inventory:
                self.inventory[key] = dep
            else:
                # Merge manifest metadata
                existing = self.inventory[key]
                if dep.declared_requirement and not existing.declared_requirement:
                    existing.declared_requirement = dep.declared_requirement
                if dep.scope != "UNKNOWN":
                    existing.scope = dep.scope

            # Anything in a manifest is assumed direct
            self.direct_purls.add(key)
            self.inventory[key].dependency_type = DependencyType.DIRECT

    def add_lockfile_dependencies(self, deps: List[SCADependency]):
        """Add dependencies resolved in a lockfile (direct + transitive)."""
        for dep in deps:
            key = dep.package.purl or dep.package.display_name
            if key not in self.inventory:
                self.inventory[key] = dep
            else:
                existing = self.inventory[key]
                # Lockfile wins for resolved version
                if dep.resolved_version:
                    existing.resolved_version = dep.resolved_version
                    existing.resolution_status = ResolutionStatus.RESOLVED
                    existing.resolution_source = dep.resolution_source
                if dep.dependency_path and not existing.dependency_path:
                    existing.dependency_path = dep.dependency_path

            # If it's already marked as direct from manifest, keep it direct.
            # Otherwise, if lockfile says it's transitive, mark it so.
            if key not in self.direct_purls:
                self.inventory[key].dependency_type = dep.dependency_type
                if dep.dependency_type == DependencyType.DIRECT:
                    self.direct_purls.add(key)

    def finalize(self) -> List[SCADependency]:
        """Return the deduplicated, resolved inventory."""
        for key, dep in self.inventory.items():
            # If it wasn't in direct_purls, ensure it's marked transitive
            if key not in self.direct_purls:
                dep.dependency_type = DependencyType.TRANSITIVE
                
            # If there's no dependency path for a transitive, just provide a generic one
            if dep.dependency_type == DependencyType.TRANSITIVE and not dep.dependency_path:
                dep.dependency_path = ["<transitive>", dep.package.display_name]

        return list(self.inventory.values())
