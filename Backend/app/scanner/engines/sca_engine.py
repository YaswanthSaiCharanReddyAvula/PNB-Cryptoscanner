"""
QuantumShield — SCA Engine (Track B, Stage 14)

Software Composition Analysis engine that parses dependency manifests
and lockfiles to identify known cryptographic libraries, map their versions against a
vulnerability database, and flag deprecated or unsafe crypto wrappers.
"""

from __future__ import annotations

import os
from typing import List, Dict, Any

from app.scanner.models import StageResult
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

from app.scanner.sca.discovery.manifest_discovery import discover_manifests
from app.scanner.sca.parsers.python_manifest import (
    parse_requirements_txt, parse_pyproject_toml, parse_pipfile,
    parse_poetry_lock, parse_pipfile_lock
)
from app.scanner.sca.parsers.npm_manifest import (
    parse_package_json, parse_package_lock_json, parse_yarn_lock
)
from app.scanner.sca.parsers.java_go_manifest import (
    parse_pom_xml, parse_go_mod, parse_go_sum
)
from app.scanner.sca.graph.dependency_graph import DependencyGraphBuilder
from app.scanner.sca.vulnerability.matcher import VulnerabilityDatabase, match_vulnerabilities
from app.scanner.sca.crypto.package_registry import CryptoRegistry

logger = get_logger(__name__)


class SCAEngine(ScanStage):
    """Track B — Stage 14: Software Composition Analysis for crypto libs."""

    name = "sca_engine"
    order = 21
    timeout_seconds = 60  # Increased for deep lockfiles
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields: list[str] = []
    writes_fields = ["sca_findings"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        source_paths: list[str] = []

        raw = ctx.options.get("source_code_paths") or ctx.options.get("source_code_path")
        if isinstance(raw, str):
            source_paths = [raw]
        elif isinstance(raw, list):
            source_paths = [str(p) for p in raw]

        if not source_paths:
            logger.info("[%s] SCA: no source_code_paths configured — skipping", ctx.scan_id)
            return StageResult(
                status="skipped",
                data={"sca_findings": []},
                error="No source_code_paths provided in scan options",
            )

        # 1. Load Vulnerability Database
        vuln_db = VulnerabilityDatabase()
        vuln_db.load()

        if vuln_db.status == "VULNERABILITY_DATA_UNAVAILABLE":
            return StageResult(
                status="skipped",
                data={"sca_findings": []},
                error="Vulnerability database unavailable or missing",
            )

        all_findings = []

        for base_path in source_paths:
            if not os.path.isdir(base_path):
                continue
            
            # 2. Discover files
            discovery = discover_manifests(base_path)
            
            # Organize by project directory to build correct graphs per project
            projects: Dict[str, Dict[str, list]] = {}
            
            for m in discovery.manifests:
                if m.project_dir not in projects:
                    projects[m.project_dir] = {"manifests": [], "lockfiles": []}
                projects[m.project_dir]["manifests"].append(m)
                
            for l in discovery.lockfiles:
                if l.project_dir not in projects:
                    projects[l.project_dir] = {"manifests": [], "lockfiles": []}
                projects[l.project_dir]["lockfiles"].append(l)

            # 3. Parse and build graph per project
            for proj_dir, files in projects.items():
                graph_builder = DependencyGraphBuilder()
                
                # Parse manifests
                for m in files["manifests"]:
                    deps = self._parse_manifest(m)
                    for d in deps: d.project_id = proj_dir
                    graph_builder.add_manifest_dependencies(deps)
                    
                # Parse lockfiles
                for l in files["lockfiles"]:
                    deps = self._parse_lockfile(l)
                    for d in deps: d.project_id = proj_dir
                    graph_builder.add_lockfile_dependencies(deps)
                    
                resolved_deps = graph_builder.finalize()
                
                # 4. Crypto Relevance & Vulnerability Correlation
                for dep in resolved_deps:
                    crypto_meta = CryptoRegistry.lookup(dep.package)
                    if crypto_meta:
                        # Enhance dependency with crypto relevance
                        
                        # Match vulnerabilities
                        vulns = match_vulnerabilities(dep, vuln_db, ctx.scan_id)
                        
                        if vulns:
                            for v in vulns:
                                v.crypto_relevance = crypto_meta.crypto_relevance
                                v.crypto_primitives = crypto_meta.primitives
                                v.pqc_relevance = ", ".join(crypto_meta.pqc_support) if crypto_meta.pqc_support else None
                                all_findings.append(v.model_dump())
                        else:
                            # Even if not vulnerable, it's a crypto dependency finding
                            from app.scanner.sca.models.package import VulnerabilityStatus, Confidence
                            
                            safe_finding = match_vulnerabilities(dep, vuln_db, ctx.scan_id)
                            # Create a clean finding without vuln
                            from app.scanner.sca.models.package import SCAFindingV2
                            finding = SCAFindingV2(
                                finding_id=f"{ctx.scan_id}-{dep.package.purl}-clean",
                                scan_id=ctx.scan_id,
                                package=dep.package,
                                resolved_version=dep.resolved_version,
                                declared_requirement=dep.declared_requirement,
                                resolution_status=dep.resolution_status,
                                dependency_type=dep.dependency_type,
                                scope=dep.scope,
                                dependency_path=dep.dependency_path,
                                vulnerability_status=VulnerabilityStatus.NOT_VULNERABLE,
                                manifest_file=dep.resolution_source,
                                project_id=proj_dir,
                                confidence=Confidence.HIGH if dep.resolved_version else Confidence.MEDIUM,
                                crypto_relevance=crypto_meta.crypto_relevance,
                                crypto_primitives=crypto_meta.primitives,
                                pqc_relevance=", ".join(crypto_meta.pqc_support) if crypto_meta.pqc_support else None
                            )
                            all_findings.append(finding.model_dump())


        logger.info(
            "[%s] SCA: completed — %d crypto dependencies found",
            ctx.scan_id, len(all_findings),
        )

        return StageResult(
            status="completed",
            data={"sca_findings": all_findings},
        )

    def _parse_manifest(self, m: Any) -> list:
        lower = m.filename.lower()
        if lower == "requirements.txt" or (lower.startswith("requirements") and lower.endswith(".txt")):
            return parse_requirements_txt(m.file_path)
        elif lower == "pyproject.toml":
            return parse_pyproject_toml(m.file_path)
        elif lower == "pipfile":
            return parse_pipfile(m.file_path)
        elif lower == "package.json":
            return parse_package_json(m.file_path)
        elif lower == "pom.xml":
            return parse_pom_xml(m.file_path)
        elif lower == "go.mod":
            return parse_go_mod(m.file_path)
        return []

    def _parse_lockfile(self, l: Any) -> list:
        lower = l.filename.lower()
        if lower == "poetry.lock":
            return parse_poetry_lock(l.file_path)
        elif lower == "pipfile.lock":
            return parse_pipfile_lock(l.file_path)
        elif lower == "package-lock.json":
            return parse_package_lock_json(l.file_path)
        elif lower == "yarn.lock":
            return parse_yarn_lock(l.file_path)
        elif lower == "go.sum":
            return parse_go_sum(l.file_path)
        return []
