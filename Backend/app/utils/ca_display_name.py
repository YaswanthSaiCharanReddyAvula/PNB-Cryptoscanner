"""
Map raw X.509 issuer strings (from testssl/openssl) to short, real-world CA labels for charts and tables.
"""

from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

# (substring match, canonical display name) — order: more specific phrases first
_CA_SUBSTRING_RULES: Tuple[Tuple[str, str], ...] = (
    ("Internet Security Research Group", "Let's Encrypt"),
    ("Let's Encrypt", "Let's Encrypt"),
    ("Google Trust Services", "Google Trust Services"),
    ("DigiCert", "DigiCert"),
    ("Amazon Web Services", "Amazon (AWS)"),
    ("Amazon", "Amazon (AWS)"),
    ("Sectigo", "Sectigo"),
    ("USERTrust", "Sectigo"),
    ("COMODO", "Sectigo"),
    ("Comodo", "Sectigo"),
    ("GlobalSign", "GlobalSign"),
    ("GoDaddy", "GoDaddy"),
    ("Go Daddy", "GoDaddy"),
    ("Entrust", "Entrust"),
    ("Microsoft Corporation", "Microsoft"),
    ("Microsoft", "Microsoft"),
    ("Cloudflare", "Cloudflare"),
    ("Buypass", "Buypass"),
    ("ZeroSSL", "ZeroSSL"),
    ("SSL.com", "SSL.com"),
    ("IdenTrust", "IdenTrust"),
    ("Actalis", "Actalis"),
    ("SwissSign", "SwissSign"),
    ("QuoVadis", "QuoVadis"),
    ("HARICA", "HARICA"),
    ("GTS", "Google Trust Services"),
    ("Apple Inc", "Apple"),
    ("Apple", "Apple"),
    ("Cisco", "Cisco"),
    ("WISeKey", "WISeKey"),
    ("Trustwave", "Trustwave"),
    ("Network Solutions", "Network Solutions"),
    ("Starfield", "GoDaddy"),
    ("GeoTrust", "DigiCert"),
    ("Thawte", "DigiCert"),
    ("RapidSSL", "DigiCert"),
    ("Symantec", "DigiCert"),
    ("VeriSign", "DigiCert"),
    ("Certum", "Asseco"),
    ("Asseco", "Asseco"),
    ("Telekom", "Deutsche Telekom"),
    ("Deutsche Telekom", "Deutsche Telekom"),
    ("FNMT", "FNMT-RCM"),
    ("AC RAIZ", "AC Raíz"),
    ("AC Camerfirma", "Camerfirma"),
    ("Autoridad de Certificación", "ANF AC"),
)


def _parse_dn_attributes(issuer: str) -> Dict[str, str]:
    """Best-effort LDAP DN component extraction (handles spaces around =)."""
    out: Dict[str, str] = {}
    if not issuer or "=" not in issuer:
        return out
    for m in re.finditer(r"(?:^|,)\s*([A-Za-z]+)\s*=\s*([^,]+?)(?=\s*,\s*[A-Za-z]+\s*=|$)", issuer.strip()):
        key = m.group(1).upper()
        val = m.group(2).strip()
        if val:
            out[key] = val
    return out


def _canonical_from_blob(blob: str) -> Optional[str]:
    if not blob:
        return None
    upper_ready = blob
    for needle, label in _CA_SUBSTRING_RULES:
        if needle.lower() in upper_ready.lower():
            return label
    return None


def _organization_display(o: str) -> str:
    o = re.sub(r"\s+", " ", o.strip())
    o = re.sub(
        r",?\s*(Inc\.?|LLC|Ltd\.?|L\.P\.|Corp\.?|Corporation|Limited|plc|PLC|GmbH|AG|SA|BV)\.?$",
        "",
        o,
        flags=re.I,
    ).strip()
    return o[:64] if len(o) > 64 else o


def normalize_ca_display_name(raw: Optional[str]) -> str:
    """
    Turn a raw issuer field into a short label suitable for pie charts and KPIs.

    Examples:
      "CN=R3, O=Let's Encrypt, C=US" -> "Let's Encrypt"
      "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US" -> "DigiCert"
    """
    if raw is None:
        return "Unknown"
    s = str(raw).strip()
    if not s or s.lower() in ("unknown", "n/a", "none", "-", "null"):
        return "Unknown"

    canon = _canonical_from_blob(s)
    if canon:
        return canon

    attrs = _parse_dn_attributes(s)
    combined = " ".join(attrs.values()) if attrs else s
    canon = _canonical_from_blob(combined)
    if canon:
        return canon

    o = attrs.get("O")
    if o:
        short = _organization_display(o)
        again = _canonical_from_blob(short)
        if again:
            return again
        return short if short else "Unknown"

    cn = attrs.get("CN")
    if cn and len(cn.strip()) > 2:
        cn_clean = cn.strip()
        c2 = _canonical_from_blob(cn_clean)
        if c2:
            return c2
        # Very short CN (e.g. "R3") is not meaningful alone
        if len(cn_clean) <= 4:
            return "Unknown"
        return cn_clean[:64]

    # Non-DN single line
    if len(s) <= 72:
        return s
    return s[:69] + "…"


def extract_issuer_raw_from_tls_row(t: dict) -> Optional[str]:
    """Prefer leaf cert issuer; else first chain entry with an issuer field."""
    cert = t.get("certificate") or {}
    iss = cert.get("issuer")
    if iss:
        return str(iss).strip() or None
    for entry in t.get("cert_chain") or []:
        if isinstance(entry, dict) and entry.get("issuer"):
            return str(entry["issuer"]).strip() or None
    return None
