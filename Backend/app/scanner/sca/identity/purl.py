"""
QuantumShield — PURL (Package URL) Generation

Implements the PURL specification for canonical package identity.
"""

from __future__ import annotations
from app.scanner.sca.models.package import Ecosystem


def generate_purl(
    ecosystem: Ecosystem,
    name: str,
    version: str | None = None,
    namespace: str | None = None,
) -> str:
    """Generate a Package URL per the purl-spec."""
    eco_map = {
        Ecosystem.PYPI: "pypi",
        Ecosystem.NPM: "npm",
        Ecosystem.MAVEN: "maven",
        Ecosystem.GO: "golang",
        Ecosystem.CARGO: "cargo",
        Ecosystem.NUGET: "nuget",
        Ecosystem.COMPOSER: "composer",
        Ecosystem.RUBYGEMS: "gem",
    }
    purl_type = eco_map.get(ecosystem, "generic")

    # Normalize per ecosystem conventions
    normalized_name = name
    if ecosystem == Ecosystem.PYPI:
        normalized_name = name.lower().replace("_", "-")
    elif ecosystem == Ecosystem.NPM:
        normalized_name = name  # npm is case-sensitive

    parts = [f"pkg:{purl_type}/"]
    if namespace:
        parts.append(f"{namespace}/")
    parts.append(normalized_name)
    if version:
        parts.append(f"@{version}")

    return "".join(parts)


def normalize_package_name(ecosystem: Ecosystem, name: str) -> str:
    """Normalize a package name per ecosystem conventions."""
    if ecosystem == Ecosystem.PYPI:
        return name.lower().replace("_", "-").replace(".", "-")
    if ecosystem == Ecosystem.NPM:
        return name  # npm is case-sensitive
    if ecosystem == Ecosystem.MAVEN:
        return name  # Maven uses groupId:artifactId
    if ecosystem == Ecosystem.GO:
        return name.lower()
    if ecosystem == Ecosystem.CARGO:
        return name.lower().replace("_", "-")
    if ecosystem == Ecosystem.NUGET:
        return name.lower()
    if ecosystem == Ecosystem.COMPOSER:
        return name.lower()
    if ecosystem == Ecosystem.RUBYGEMS:
        return name.lower()
    return name.lower()
