"""
Shared JSON export bundle builder (same payload as GET /reports/export-bundle).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from app.modules.threat_nist_mapping import NIST_PQC_REFERENCES


async def build_export_bundle_payload(
    db,
    scans_collection: str,
    domain: Optional[str],
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Returns (payload_dict, scan_doc) or raises LookupError if no completed scan.
    """
    query: dict = {"status": "completed"}
    if domain:
        d = domain.strip().lower()
        if d:
            query["domain"] = d

    doc = await db[scans_collection].find_one(query, sort=[("completed_at", -1)])
    if not doc:
        raise LookupError("No completed scan found")

    exported_at = datetime.utcnow().isoformat() + "Z"
    payload: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "exported_at": exported_at,
        "domain": doc.get("domain"),
        "completed_at": doc.get("completed_at"),
        "threat_nist_context": {
            "nist_pqc_publications": NIST_PQC_REFERENCES,
            "note": "Per-component threat vectors and NIST mapping are included in GET /cbom/per-app responses.",
        },
        "audit_metadata": {
            "cbom_schema": (doc.get("cbom_report") or {}).get("schema_version", "1.0.0"),
            "quantum_scoring": {
                "formula": "weighted_mean_of_category_minimums",
                "weights": {
                    "key_exchange": 0.4,
                    "signature": 0.3,
                    "cipher": 0.2,
                    "protocol": 0.1,
                },
                "reference": "app/modules/quantum_risk_engine.py",
            },
            "tls_pqc_signals": {
                "note": (
                    "Cipher/KEX name substrings only (e.g. Kyber); not proof of PQC libraries in use."
                ),
                "reference": "app/modules/tls_pqc_signals.py",
            },
        },
        "cbom_report": doc.get("cbom_report"),
        "cbom_legacy": doc.get("cbom", []),
        "quantum_score": doc.get("quantum_score"),
        "recommendations": doc.get("recommendations", []),
        "tls_results": doc.get("tls_results", []),
        "assets": doc.get("assets", []),
        "cve_findings": doc.get("cve_findings", []),
        "vuln_findings": doc.get("vuln_findings", []),
    }
    return payload, doc
