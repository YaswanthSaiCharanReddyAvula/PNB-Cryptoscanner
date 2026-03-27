"""
Phase 3 — Map quantum threat models to NIST PQC guidance (indicative, not certification).

Used to enrich CBOM rows, migration backlog, and score simulations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Curated NIST PQC publication pointers (human-readable; verify before compliance use)
NIST_PQC_REFERENCES: Dict[str, Dict[str, str]] = {
    "FIPS_203": {
        "label": "FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)",
        "url": "https://csrc.nist.gov/projects/post-quantum-cryptography/fips-203",
    },
    "FIPS_204": {
        "label": "FIPS 204 — Module-Lattice-Based Digital Signature (ML-DSA)",
        "url": "https://csrc.nist.gov/projects/post-quantum-cryptography/fips-204",
    },
    "FIPS_205": {
        "label": "FIPS 205 — Stateless Hash-Based Digital Signature (SLH-DSA)",
        "url": "https://csrc.nist.gov/projects/post-quantum-cryptography/fips-205",
    },
    "SP_800_208": {
        "label": "NIST SP 800-208 — Recommendations for TLS",
        "url": "https://csrc.nist.gov/publications/detail/sp/800-208/final",
    },
}


def infer_threat_from_category(category: str) -> str:
    c = (category or "").lower()
    if c in ("key_exchange", "signature"):
        return "shor"
    if c in ("cipher", "hash"):
        return "grover"
    return "hndl"


def nist_guidance_for_component(category: str, threat: str, name: str) -> Dict[str, Any]:
    """Return recommended NIST family + refs for a CBOM component."""
    c = (category or "").lower()
    t = (threat or "").lower()
    nl = (name or "").lower()

    primary_nist: Optional[str] = None
    secondary_refs: List[str] = []
    summary = ""

    if c == "key_exchange" or ("kyber" in nl or "ml-kem" in nl or "mlkem" in nl):
        primary_nist = "ML-KEM (FIPS 203)"
        secondary_refs = ["FIPS_203", "SP_800_208"]
        summary = "Transition to ML-KEM / hybrid TLS key exchange (e.g. X25519Kyber) per org crypto policy."
    elif c == "signature" or "rsa" in nl or "ecdsa" in nl or "dsa" in nl:
        primary_nist = "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"
        secondary_refs = ["FIPS_204", "FIPS_205"]
        summary = "Plan hybrid certificates and ML-DSA / SLH-DSA for long-lived signatures."
    elif c in ("cipher", "hash"):
        primary_nist = "AES-256 + SHA-256/SHA-384 (Grover margin)"
        secondary_refs = ["SP_800_208"]
        summary = "Prefer AES-256-GCM and SHA-256+ for data with long confidentiality needs."
    else:
        primary_nist = "TLS 1.3 + crypto-agility"
        secondary_refs = ["SP_800_208", "FIPS_203"]
        summary = "Reduce HNDL exposure: TLS 1.3, forward secrecy, PQC KEM when available."

    refs_out = [NIST_PQC_REFERENCES[k] for k in secondary_refs if k in NIST_PQC_REFERENCES]

    return {
        "threat_vector": t or infer_threat_from_category(category),
        "nist_primary_recommendation": primary_nist,
        "nist_summary": summary,
        "nist_reference_urls": refs_out,
    }


def enrich_cbom_component_dict(row: Dict[str, Any]) -> Dict[str, Any]:
    """Merge threat/NIST fields into a serialized CBOM component (Mongo/API)."""
    cat = row.get("category") or ""
    threat = row.get("primary_quantum_threat") or infer_threat_from_category(str(cat))
    g = nist_guidance_for_component(str(cat), str(threat), str(row.get("name") or ""))
    out = {**row, **g}
    return out


def _crit_weight(criticality: Optional[str]) -> float:
    m = (criticality or "").strip().lower()
    return {
        "critical": 4.0,
        "high": 3.0,
        "medium": 2.0,
        "low": 1.0,
    }.get(m, 1.5)


def _tls_issue_weight(tls: Dict[str, Any]) -> float:
    """Higher = more urgent to remediate."""
    w = 1.0
    v = str(tls.get("tls_version") or "")
    if any(x in v for x in ("1.0", "1.1", "SSL", "ssl")):
        w += 4.0
    elif "1.2" in v:
        w += 1.5
    if not v and tls.get("host"):
        w += 3.0
    cert = tls.get("certificate") or {}
    days = cert.get("days_until_expiry")
    if days is not None and days <= 30:
        w += 2.0
    if tls.get("pqc_kem_observed"):
        w -= 1.0
    return max(0.5, w)


def build_prioritized_backlog(
    scan: Dict[str, Any],
    metadata_by_host: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Ordered backlog items: criticality × TLS severity × threat alignment."""
    tls_list = scan.get("tls_results") or []
    tls_map = {t.get("host"): t for t in tls_list}
    items: List[Dict[str, Any]] = []

    for a in scan.get("assets") or []:
        host = (a.get("subdomain") or "").strip().lower()
        if not host:
            continue
        tls = tls_map.get(host, {})
        meta = metadata_by_host.get(host, {})
        crit = _crit_weight(a.get("criticality") or meta.get("criticality"))
        sev = _tls_issue_weight(tls)
        tv = "shor"
        if tls.get("tls_version") and "1.3" in str(tls.get("tls_version")):
            tv = "hndl"
        nist = nist_guidance_for_component("key_exchange", tv, str(tls.get("cipher_suite") or ""))
        score = round(crit * sev, 2)
        items.append(
            {
                "host": host,
                "priority_score": score,
                "criticality": a.get("criticality") or meta.get("criticality"),
                "environment": a.get("environment") or meta.get("environment"),
                "owner": a.get("owner") or meta.get("owner"),
                "threat_vector": nist.get("threat_vector"),
                "nist_primary_recommendation": nist.get("nist_primary_recommendation"),
                "tls_version": tls.get("tls_version"),
                "pqc_kem_observed": tls.get("pqc_kem_observed"),
                "reason": nist.get("nist_summary"),
            }
        )

    items.sort(key=lambda x: -x["priority_score"])
    return items[:80]


def simulate_quantum_score(
    scan: Dict[str, Any],
    assume_tls_13_all: bool,
    assume_pqc_hybrid_kem: bool,
) -> Dict[str, Any]:
    """Heuristic what-if projection on 0–100 quantum score (same scale as engine)."""
    qs = scan.get("quantum_score") or {}
    base = float(qs.get("score") or 0)
    tls = scan.get("tls_results") or []
    n = max(len(tls), 1)
    legacy = 0
    for t in tls:
        v = str(t.get("tls_version") or "")
        if v and "1.3" not in v and "TLSv1.3" not in v.upper():
            legacy += 1
        elif not v:
            legacy += 1

    delta = 0.0
    if assume_tls_13_all:
        delta += min(22.0, (legacy / n) * 28.0)
    if assume_pqc_hybrid_kem:
        non_pq = sum(1 for t in tls if not (t.get("pqc_kem_observed") or t.get("hybrid_key_exchange")))
        delta += min(14.0, (non_pq / n) * 14.0)

    projected = round(min(100.0, base + delta), 1)
    return {
        "baseline_score": base,
        "projected_score": projected,
        "delta": round(projected - base, 1),
        "assumptions": {
            "assume_tls_13_all": assume_tls_13_all,
            "assume_pqc_hybrid_kem": assume_pqc_hybrid_kem,
        },
        "note": "Indicative only — not a replacement for lab validation or formal crypto review.",
    }
