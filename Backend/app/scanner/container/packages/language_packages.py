"""
QuantumShield — Static Language Package & Manifest Discovery

Discovers language dependencies (Python, Node, Java, Go, Rust) directly
from filesystem manifests without running build tools or package managers.
"""

from __future__ import annotations

import json
import os
import re
from typing import List, Optional

from app.scanner.container.models import ConfidenceLevel, PackageObservation
from app.utils.logger import get_logger

logger = get_logger(__name__)


class LanguagePackageParser:
    """Discovers application packages from lockfiles and manifests."""

    @classmethod
    def parse_manifest(cls, filepath: str) -> List[PackageObservation]:
        """Inspect a file artifact and extract declared dependencies."""
        packages: List[PackageObservation] = []
        if not os.path.isfile(filepath):
            return packages

        basename = os.path.basename(filepath).lower()

        # 1. Node.js package.json
        if basename == "package.json":
            packages.extend(cls._parse_package_json(filepath))

        # 2. Python requirements.txt
        elif basename in ("requirements.txt", "requirements.in"):
            packages.extend(cls._parse_python_requirements(filepath))

        # 3. Python dist-info METADATA
        elif basename == "metadata" and ".dist-info" in filepath:
            pkg = cls._parse_python_dist_info(filepath)
            if pkg:
                packages.append(pkg)

        # 4. Go go.mod
        elif basename == "go.mod":
            packages.extend(cls._parse_go_mod(filepath))

        # 5. Java pom.xml
        elif basename == "pom.xml":
            packages.extend(cls._parse_pom_xml(filepath))

        return packages

    @classmethod
    def _parse_package_json(cls, filepath: str) -> List[PackageObservation]:
        """Parse package.json dependencies."""
        packages = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            deps = data.get("dependencies") or {}
            for name, ver in deps.items():
                packages.append(
                    PackageObservation(
                        ecosystem="npm",
                        name=name,
                        version=str(ver).lstrip("^~>=<"),
                        source_file=filepath,
                        confidence=ConfidenceLevel.HIGH,
                    )
                )
        except Exception as exc:
            logger.debug("Failed parsing package.json %s: %s", filepath, exc)
        return packages

    @classmethod
    def _parse_python_requirements(cls, filepath: str) -> List[PackageObservation]:
        """Parse requirements.txt."""
        packages = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Match: package==1.2.3 or package>=1.2.3
                m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[=><~!]=?\s*([0-9a-zA-Z\.\-]+))?", line)
                if m:
                    name = m.group(1).lower()
                    ver = m.group(2)
                    packages.append(
                        PackageObservation(
                            ecosystem="pypi",
                            name=name,
                            version=ver,
                            source_file=filepath,
                            confidence=ConfidenceLevel.HIGH,
                        )
                    )
        except Exception as exc:
            logger.debug("Failed parsing requirements.txt %s: %s", filepath, exc)
        return packages

    @classmethod
    def _parse_python_dist_info(cls, filepath: str) -> Optional[PackageObservation]:
        """Parse Python installed wheel .dist-info/METADATA."""
        try:
            name, ver = None, None
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("Name:"):
                        name = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:"):
                        ver = line.split(":", 1)[1].strip()
                    if name and ver:
                        break
            if name:
                return PackageObservation(
                    ecosystem="pypi",
                    name=name,
                    version=ver,
                    source_file=filepath,
                    confidence=ConfidenceLevel.HIGH,
                )
        except Exception:
            pass
        return None

    @classmethod
    def _parse_go_mod(cls, filepath: str) -> List[PackageObservation]:
        """Parse go.mod file."""
        packages = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            in_require = False
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("require ("):
                    in_require = True
                    continue
                if in_require and line == ")":
                    in_require = False
                    continue
                if in_require or line.startswith("require "):
                    parts = line.replace("require ", "").split()
                    if len(parts) >= 2:
                        packages.append(
                            PackageObservation(
                                ecosystem="go",
                                name=parts[0],
                                version=parts[1].lstrip("v"),
                                source_file=filepath,
                                confidence=ConfidenceLevel.HIGH,
                            )
                        )
        except Exception as exc:
            logger.debug("Failed parsing go.mod %s: %s", filepath, exc)
        return packages

    @classmethod
    def _parse_pom_xml(cls, filepath: str) -> List[PackageObservation]:
        """Extract dependencies from Maven pom.xml."""
        packages = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Simple regex search for <dependency> blocks
            dep_pattern = re.compile(
                r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?",
                re.DOTALL,
            )
            for m in dep_pattern.finditer(content):
                group = m.group(1).strip()
                artifact = m.group(2).strip()
                ver = m.group(3).strip() if m.group(3) else None
                packages.append(
                    PackageObservation(
                        ecosystem="maven",
                        name=f"{group}:{artifact}",
                        version=ver,
                        source_file=filepath,
                        confidence=ConfidenceLevel.HIGH,
                    )
                )
        except Exception as exc:
            logger.debug("Failed parsing pom.xml %s: %s", filepath, exc)
        return packages
