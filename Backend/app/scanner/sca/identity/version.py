"""
QuantumShield — Semantic Version Comparator

Ecosystem-appropriate version parsing and range matching.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple


def _parse_version_tuple(version: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of integers for comparison."""
    # Strip leading 'v' common in Go
    v = version.lstrip("vV")
    # Extract numeric parts, ignoring pre-release/build suffixes
    parts = re.split(r"[^0-9]+", v.split("-")[0].split("+")[0])
    result = []
    for p in parts:
        if p:
            try:
                result.append(int(p))
            except ValueError:
                break
    return tuple(result) if result else (0,)


def version_lt(a: str, b: str) -> bool:
    return _parse_version_tuple(a) < _parse_version_tuple(b)


def version_le(a: str, b: str) -> bool:
    return _parse_version_tuple(a) <= _parse_version_tuple(b)


def version_gt(a: str, b: str) -> bool:
    return _parse_version_tuple(a) > _parse_version_tuple(b)


def version_ge(a: str, b: str) -> bool:
    return _parse_version_tuple(a) >= _parse_version_tuple(b)


def version_eq(a: str, b: str) -> bool:
    return _parse_version_tuple(a) == _parse_version_tuple(b)


def version_in_range(version: str, range_spec: str) -> Optional[bool]:
    """
    Evaluate whether `version` satisfies `range_spec`.

    Supports: <, <=, >, >=, ==, =, !=, ^, ~
    Compound: comma-separated constraints.

    Returns True/False, or None if the range cannot be parsed.
    """
    if not version or not range_spec:
        return None

    range_spec = range_spec.strip()

    # Compound constraints: ">=1.0.0,<2.0.0" or ">=1.0.0 <2.0.0"
    parts = [p.strip() for p in re.split(r"[,\s]+", range_spec) if p.strip()]
    if not parts:
        return None

    for part in parts:
        result = _eval_single_constraint(version, part)
        if result is None:
            return None
        if not result:
            return False
    return True


def _eval_single_constraint(version: str, constraint: str) -> Optional[bool]:
    """Evaluate a single version constraint."""
    constraint = constraint.strip()
    if not constraint:
        return None

    # Wildcard or star
    if constraint in ("*", "latest", "x", "X"):
        return True

    # Caret: ^1.2.3 means >=1.2.3, <2.0.0 (for major > 0)
    if constraint.startswith("^"):
        base = constraint[1:].strip()
        t = _parse_version_tuple(base)
        if not t:
            return None
        if t[0] > 0:
            return version_ge(version, base) and version_lt(
                version, f"{t[0] + 1}.0.0"
            )
        elif len(t) > 1 and t[1] > 0:
            return version_ge(version, base) and version_lt(
                version, f"0.{t[1] + 1}.0"
            )
        else:
            return version_eq(version, base)

    # Tilde: ~1.2.3 means >=1.2.3, <1.3.0
    if constraint.startswith("~"):
        base = constraint[1:].strip()
        # ~= is PEP 440 compatible release
        if base.startswith("="):
            base = base[1:].strip()
        t = _parse_version_tuple(base)
        if not t:
            return None
        if len(t) >= 2:
            return version_ge(version, base) and version_lt(
                version, f"{t[0]}.{t[1] + 1}.0"
            )
        else:
            return version_ge(version, base) and version_lt(
                version, f"{t[0] + 1}.0.0"
            )

    # Operators: >=, <=, !=, ==, >, <, =
    for op in (">=", "<=", "!=", "==", ">", "<", "="):
        if constraint.startswith(op):
            target = constraint[len(op):].strip()
            if not target:
                return None
            if op == ">=":
                return version_ge(version, target)
            elif op == "<=":
                return version_le(version, target)
            elif op == ">":
                return version_gt(version, target)
            elif op == "<":
                return version_lt(version, target)
            elif op in ("==", "="):
                return version_eq(version, target)
            elif op == "!=":
                return not version_eq(version, target)

    # Plain version: assume exact match
    if re.match(r"^[0-9]", constraint):
        return version_eq(version, constraint)

    return None


def is_version_affected(version: str, affected_ranges: list[dict]) -> Optional[bool]:
    """
    Evaluate OSV-style affected ranges.

    Each range dict may have:
      - type: "SEMVER" | "ECOSYSTEM" | "GIT"
      - events: [{"introduced": "0"}, {"fixed": "1.2.3"}]
      - Or simple: {"min": "...", "max": "...", "max_inclusive": True}
    """
    if not version or not affected_ranges:
        return None

    for r in affected_ranges:
        events = r.get("events", [])
        if events:
            result = _eval_osv_events(version, events)
            if result:
                return True
        else:
            # Simple range format
            min_v = r.get("min") or r.get("introduced")
            max_v = r.get("max") or r.get("fixed") or r.get("max_affected_version")
            if min_v and max_v:
                max_inclusive = r.get("max_inclusive", False)
                if version_ge(version, min_v):
                    if max_inclusive:
                        if version_le(version, max_v):
                            return True
                    else:
                        if version_lt(version, max_v):
                            return True
            elif max_v:
                max_inclusive = r.get("max_inclusive", False)
                if max_inclusive:
                    if version_le(version, max_v):
                        return True
                else:
                    if version_lt(version, max_v):
                        return True

    return False


def _eval_osv_events(version: str, events: list[dict]) -> bool:
    """Evaluate OSV event-based ranges."""
    introduced = None
    fixed = None
    last_affected = None

    for event in events:
        if "introduced" in event:
            introduced = event["introduced"]
        elif "fixed" in event:
            fixed = event["fixed"]
        elif "last_affected" in event:
            last_affected = event["last_affected"]

    if introduced is None:
        return False

    # "0" means from the beginning
    if introduced == "0":
        after_intro = True
    else:
        after_intro = version_ge(version, introduced)

    if not after_intro:
        return False

    if fixed:
        return version_lt(version, fixed)
    elif last_affected:
        return version_le(version, last_affected)
    else:
        # Introduced but no fix known → assume still affected
        return True
