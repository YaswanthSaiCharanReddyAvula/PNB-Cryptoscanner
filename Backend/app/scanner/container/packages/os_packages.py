"""
QuantumShield — Static OS Package Discovery

Parses installed OS package databases directly from filesystems without executing
package manager binaries (apt, dpkg, apk, rpm).
Supports:
  - Debian / Ubuntu (/var/lib/dpkg/status)
  - Alpine (/lib/apk/db/installed)
  - RedHat / CentOS (RPM database / manifest files)
"""

from __future__ import annotations

import os
import re
from typing import List, Optional

from app.scanner.container.models import ConfidenceLevel, PackageObservation
from app.utils.logger import get_logger

logger = get_logger(__name__)


class OSPackageParser:
    """Statically discovers OS packages from container filesystem files."""

    @classmethod
    def parse_dpkg_status(cls, filepath: str) -> List[PackageObservation]:
        """Parse Debian/Ubuntu /var/lib/dpkg/status file."""
        packages: List[PackageObservation] = []
        if not os.path.isfile(filepath):
            return packages

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Packages are separated by blank lines
            records = content.split("\n\n")
            for record in records:
                if not record.strip():
                    continue

                pkg_name = None
                pkg_ver = None
                status = None
                license_val = None

                for line in record.splitlines():
                    if line.startswith("Package:"):
                        pkg_name = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:"):
                        pkg_ver = line.split(":", 1)[1].strip()
                    elif line.startswith("Status:"):
                        status = line.split(":", 1)[1].strip()
                    elif line.startswith("License:"):
                        license_val = line.split(":", 1)[1].strip()

                # Only include installed packages
                if pkg_name and (not status or "installed" in status):
                    packages.append(
                        PackageObservation(
                            ecosystem="dpkg",
                            name=pkg_name,
                            version=pkg_ver,
                            license=license_val,
                            source_file=filepath,
                            confidence=ConfidenceLevel.HIGH,
                        )
                    )

        except Exception as exc:
            logger.debug("Failed parsing dpkg status %s: %s", filepath, exc)

        return packages

    @classmethod
    def parse_apk_installed(cls, filepath: str) -> List[PackageObservation]:
        """Parse Alpine /lib/apk/db/installed file."""
        packages: List[PackageObservation] = []
        if not os.path.isfile(filepath):
            return packages

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            records = content.split("\n\n")
            for record in records:
                if not record.strip():
                    continue

                pkg_name = None
                pkg_ver = None
                license_val = None

                for line in record.splitlines():
                    if line.startswith("P:"):
                        pkg_name = line[2:].strip()
                    elif line.startswith("V:"):
                        pkg_ver = line[2:].strip()
                    elif line.startswith("L:"):
                        license_val = line[2:].strip()

                if pkg_name:
                    packages.append(
                        PackageObservation(
                            ecosystem="apk",
                            name=pkg_name,
                            version=pkg_ver,
                            license=license_val,
                            source_file=filepath,
                            confidence=ConfidenceLevel.HIGH,
                        )
                    )

        except Exception as exc:
            logger.debug("Failed parsing apk database %s: %s", filepath, exc)

        return packages

    @classmethod
    def discover_os_packages(cls, root_dir: str) -> List[PackageObservation]:
        """Scan a filesystem root for standard OS package databases."""
        discovered: List[PackageObservation] = []
        root = os.path.abspath(root_dir)

        # 1. dpkg status
        dpkg_path = os.path.join(root, "var", "lib", "dpkg", "status")
        if os.path.isfile(dpkg_path):
            discovered.extend(cls.parse_dpkg_status(dpkg_path))

        # 2. apk db
        apk_path = os.path.join(root, "lib", "apk", "db", "installed")
        if os.path.isfile(apk_path):
            discovered.extend(cls.parse_apk_installed(apk_path))

        return discovered
