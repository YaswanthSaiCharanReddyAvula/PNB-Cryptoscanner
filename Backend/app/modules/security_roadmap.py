"""
Security roadmap: risk findings → target solutions for TLS posture and quantum migration.

Derives rows from stored scan recommendations plus aggregated TLS/certificate signals.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

_PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "safe": 4}


def _host_port(t: Dict[str, Any]) -> str:
    h = (t.get("host") or "").strip()
    p = t.get("port")
    return f"{h}:{p}" if h and p is not None else h or "unknown"


def _is_legacy_protocol(version_str: str, proto_list: List[Any]) -> bool:
    blob = " ".join(
        [str(version_str or "")]
        + [str(p) for p in (proto_list or [])]
    ).upper()
    compact = blob.replace(" ", "").replace("_", "")
    if any(x in compact for x in ("SSLV2", "SSLV3", "SSL2", "SSL3")):
        return True
    if "TLS1.0" in compact or "TLSV1.0" in compact or "TLS10" in compact:
        return True
    if "TLS1.1" in compact or "TLSV1.1" in compact or "TLS11" in compact:
        return True
    if "TLS1" == compact or compact.endswith("TLS1"):
        return True
    return False


def _cipher_looks_legacy(cipher: str) -> bool:
    c = (cipher or "").upper()
    if not c:
        return False
    if "GCM" in c or "CHACHA" in c or "POLY1305" in c:
        return False
    return any(tok in c for tok in ("RC4", "3DES", "DES-", "MD5", "NULL", "EXPORT", "CBC"))


def _derive_tls_roadmap(tls_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    legacy_ep: Set[str] = set()
    weak_cipher_ep: Set[str] = set()
    small_key_ep: Set[str] = set()
    no_fs_ep: Set[str] = set()
    conf_by_ep: Dict[str, str] = {}

    for t in tls_results:
        if t.get("error"):
            continue
        ep = _host_port(t)
        conf = t.get("confidence")
        if conf is None:
            conf_by_ep[ep] = "low"
        else:
            conf_by_ep[ep] = str(conf)

    for t in tls_results:
        if t.get("error"):
            continue
        hp = _host_port(t)
        if _is_legacy_protocol(str(t.get("tls_version") or ""), list(t.get("all_supported_protocols") or [])):
            legacy_ep.add(hp)
        cipher = str(t.get("cipher_suite") or "")
        if _cipher_looks_legacy(cipher):
            weak_cipher_ep.add(hp)
        cert = t.get("certificate") or {}
        ks = cert.get("public_key_size")
        if isinstance(ks, int) and ks > 0 and ks < 2048:
            small_key_ep.add(hp)
        if t.get("supports_forward_secrecy") is False and cipher:
            no_fs_ep.add(hp)

    rows: List[Dict[str, Any]] = []

    def add_row(
        rid: str,
        risk: str,
        detail: str,
        solution: str,
        actions: str,
        priority: str,
        confidence: str = "medium",
    ) -> None:
        rows.append(
            {
                "id": rid,
                "source": "tls_posture",
                "risk": risk,
                "risk_detail": detail,
                "category": "transport",
                "priority": priority,
                "solution": solution,
                "actions": actions,
                "confidence": confidence,
            }
        )

    if legacy_ep:
        ep = sorted(legacy_ep)
        preview = ", ".join(ep[:15])
        if len(ep) > 15:
            preview += f" … (+{len(ep) - 15} more)"

        confs = [conf_by_ep.get(x, "low") for x in ep]
        # Worst-case confidence for safety in UI.
        confidence = "high"
        if "low" in confs:
            confidence = "low"
        elif "medium" in confs:
            confidence = "medium"

        add_row(
            "tls-legacy-protocol",
            "Legacy TLS or SSL protocol enabled",
            f"Affects {len(ep)} endpoint(s): {preview}",
            "Disable SSL, TLS 1.0, and TLS 1.1. Prefer TLS 1.3; minimum interim target TLS 1.2 with AEAD only.",
            "Update load balancers, reverse proxies, and origin configs; test clients and middleboxes; re-scan to verify.",
            "critical",
            confidence=confidence,
        )

    if weak_cipher_ep:
        ep = sorted(weak_cipher_ep)
        preview = ", ".join(ep[:15])
        if len(ep) > 15:
            preview += f" … (+{len(ep) - 15} more)"

        confs = [conf_by_ep.get(x, "low") for x in ep]
        confidence = "high"
        if "low" in confs:
            confidence = "low"
        elif "medium" in confs:
            confidence = "medium"

        add_row(
            "tls-weak-cipher",
            "Weak or obsolete cipher suite",
            f"Affects {len(ep)} endpoint(s): {preview}",
            "Prefer ECDHE (or DHE) key exchange with AES-GCM or ChaCha20-Poly1305; remove RC4, 3DES, MD5, NULL, EXPORT.",
            "Align cipher suites to an org standard profile (e.g. Mozilla intermediate); enable TLS 1.3 where possible.",
            "high",
            confidence=confidence,
        )

    if small_key_ep:
        ep = sorted(small_key_ep)
        preview = ", ".join(ep[:15])
        if len(ep) > 15:
            preview += f" … (+{len(ep) - 15} more)"

        confs = [conf_by_ep.get(x, "low") for x in ep]
        confidence = "high"
        if "low" in confs:
            confidence = "low"
        elif "medium" in confs:
            confidence = "medium"

        add_row(
            "cert-small-key",
            "Server certificate public key under 2048 bits",
            f"Affects {len(ep)} endpoint(s): {preview}",
            "Reissue certificates with at least 2048-bit RSA or ECDSA P-256 (or stronger per policy).",
            "Coordinate with PKI team; plan cutover and revocation of weak certs.",
            "high",
            confidence=confidence,
        )

    if no_fs_ep and not legacy_ep:
        ep = sorted(no_fs_ep)
        preview = ", ".join(ep[:12])
        if len(ep) > 12:
            preview += f" … (+{len(ep) - 12} more)"

        confs = [conf_by_ep.get(x, "low") for x in ep]
        confidence = "high"
        if "low" in confs:
            confidence = "low"
        elif "medium" in confs:
            confidence = "medium"

        add_row(
            "tls-forward-secrecy",
            "Forward secrecy not indicated for negotiated configuration",
            f"Observed on {len(ep)} endpoint(s): {preview}",
            "Use ECDHE- or DHE-based cipher suites so session keys are ephemeral.",
            "Prefer TLS 1.3; for TLS 1.2 disable static RSA key transport where possible.",
            "medium",
            confidence=confidence,
        )

    usable = [t for t in tls_results if not t.get("error")]
    no_hybrid = len(usable) > 0 and not any(
        bool(t.get("pqc_kem_observed") or t.get("hybrid_key_exchange")) for t in usable
    )
    if no_hybrid:
        # For PQC/hybrid absence we don't have endpoint-specific signals in this roadmap row,
        # but we still label confidence for explainability.
        add_row(
            "pqc-readiness-transport",
            "No hybrid / PQC key exchange observed on scanned endpoints",
            "External scan did not observe hybrid KEM (e.g. X25519Kyber768) or PQC signals on negotiated handshakes.",
            "Plan hybrid TLS key exchange pilots (e.g. ML-KEM with classical ECDH) on supported platforms; track NIST and vendor roadmaps.",
            "Validate client population, FIPS modules, and LB termination paths before broad rollout.",
            "low",
            confidence="low",
        )

    return rows


def build_security_roadmap(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build ordered roadmap items from a completed scan document (Mongo dict).
    """
    items: List[Dict[str, Any]] = []

    for idx, rec in enumerate(scan.get("recommendations") or []):
        if not isinstance(rec, dict):
            continue
        items.append(
            {
                "id": f"rec-{idx}",
                "source": "algorithm_assessment",
                "risk": rec.get("current_algorithm") or "Unspecified algorithm",
                "risk_detail": rec.get("rationale") or "",
                "category": str(rec.get("category", "unknown")),
                "priority": str(rec.get("priority", "medium")).lower(),
                "solution": rec.get("recommended_algorithm") or "",
                "actions": rec.get("migration_notes") or "",
                "confidence": "medium",
            }
        )

    items.extend(_derive_tls_roadmap(list(scan.get("tls_results") or [])))

    def sort_key(row: Dict[str, Any]) -> tuple:
        pr = str(row.get("priority") or "medium").lower()
        return (_PRIORITY_ORDER.get(pr, 5), row.get("id") or "")

    items.sort(key=sort_key)
    return items
