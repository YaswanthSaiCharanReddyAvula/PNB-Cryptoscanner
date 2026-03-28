"""Compare stored org TLS policy to latest scan TLS results (indicative)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def tls_version_rank(tls_ver: Optional[str]) -> Optional[float]:
    """Return numeric floor for ordering: 1.0 legacy, 1.2, 1.3; None if unknown."""
    if not tls_ver or not str(tls_ver).strip():
        return None
    u = str(tls_ver).upper().replace(" ", "")
    if "SSL" in u:
        return 0.5
    if "TLSV1.0" in u or "TLS1.0" in u or "TLSV1.1" in u or "TLS1.1" in u:
        return 1.0
    if "1.3" in u or "V1.3" in u:
        return 1.3
    if "1.2" in u or "V1.2" in u:
        return 1.2
    return None


def policy_min_rank(min_tls: Optional[str]) -> float:
    s = (min_tls or "1.2").strip()
    if s.startswith("1.3"):
        return 1.3
    return 1.2


def summarize_tls_vs_policy(
    tls_results: List[dict],
    min_tls: str,
    require_forward_secrecy: bool,
) -> Dict[str, Any]:
    """
    Count endpoints below org min TLS version; optional FS heuristic on cipher_suite.
    """
    need = policy_min_rank(min_tls)
    below = 0
    unknown = 0
    fs_flags = 0
    for t in tls_results:
        ver = t.get("tls_version")
        r = tls_version_rank(ver)
        if r is None:
            unknown += 1
            continue
        if r < need:
            below += 1
        if require_forward_secrecy:
            cs = (t.get("cipher_suite") or "").upper()
            if cs and "RSA" in cs and "ECDHE" not in cs and "DHE" not in cs and "TLS_AES" not in cs:
                fs_flags += 1
    return {
        "tls_endpoints": len(tls_results),
        "below_min_tls": below,
        "unknown_tls_version": unknown,
        "forward_secrecy_heuristic_flags": fs_flags,
        "policy_min_tls_version": min_tls,
        "require_forward_secrecy": require_forward_secrecy,
        "note": (
            "Indicative only: compares scanner TLS version strings and a simple cipher heuristic; "
            "not a formal compliance attestation."
        ),
    }
