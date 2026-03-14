"""
QuantumShield — CVE Mapper

Maps discovered TLS/crypto configurations to known CVEs and
well-known cryptographic attacks. This is a static mapping
engine — no external API required.
"""

from typing import List

from app.db.models import CVEFinding, RiskLevel, TLSInfo
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Known CVE / Attack database ──────────────────────────────────

CVE_DATABASE = [
    # ── Protocol vulnerabilities ──
    {
        "id": "CVE-2014-3566",
        "name": "POODLE",
        "severity": RiskLevel.HIGH,
        "description": "Padding Oracle On Downgraded Legacy Encryption. Allows decryption of SSL 3.0 traffic using a padding oracle side-channel attack.",
        "mitigation": "Disable SSLv3 entirely. Use TLS 1.2+ only.",
        "match": lambda tls: "SSLv3" in (tls.all_supported_protocols or []),
    },
    {
        "id": "CVE-2011-3389",
        "name": "BEAST",
        "severity": RiskLevel.MEDIUM,
        "description": "Browser Exploit Against SSL/TLS. Exploits CBC ciphers in TLS 1.0 to decrypt HTTPS cookies.",
        "mitigation": "Disable TLS 1.0. Use TLS 1.2+ with AEAD ciphers (GCM).",
        "match": lambda tls: "TLSv1" in (tls.all_supported_protocols or []) and "TLSv1" != "TLSv1.1",
    },
    {
        "id": "CVE-2015-0204",
        "name": "FREAK",
        "severity": RiskLevel.HIGH,
        "description": "Factoring RSA Export Keys. Allows man-in-the-middle to force export-grade RSA keys (512-bit).",
        "mitigation": "Disable all EXPORT cipher suites.",
        "match": lambda tls: any("EXPORT" in (c.get("name", "").upper()) for c in (tls.all_supported_ciphers or [])),
    },
    {
        "id": "CVE-2015-4000",
        "name": "Logjam",
        "severity": RiskLevel.HIGH,
        "description": "Allows man-in-the-middle to downgrade TLS connections to 512-bit DH export-grade cryptography.",
        "mitigation": "Disable DHE_EXPORT. Use 2048-bit DH groups minimum.",
        "match": lambda tls: any("DHE" in c.get("name", "").upper() and c.get("bits", 0) < 1024 for c in (tls.all_supported_ciphers or [])),
    },
    {
        "id": "CVE-2013-2566",
        "name": "RC4 Bias Attack",
        "severity": RiskLevel.HIGH,
        "description": "Statistical biases in RC4 keystream allow partial plaintext recovery after ~2^24 TLS connections.",
        "mitigation": "Disable all RC4 cipher suites. RFC 7465 prohibits RC4 in TLS.",
        "match": lambda tls: any("RC4" in c.get("name", "").upper() for c in (tls.all_supported_ciphers or [])),
    },
    {
        "id": "CVE-2016-2107",
        "name": "Padding Oracle (AES-CBC)",
        "severity": RiskLevel.MEDIUM,
        "description": "AES-CBC padding oracle vulnerability in OpenSSL allows decryption of TLS traffic.",
        "mitigation": "Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305). Disable CBC mode ciphers.",
        "match": lambda tls: any("CBC" in c.get("name", "").upper() for c in (tls.all_supported_ciphers or [])),
    },
    {
        "id": "CVE-2016-0800",
        "name": "DROWN",
        "severity": RiskLevel.CRITICAL,
        "description": "Decrypting RSA with Obsolete and Weakened eNcryption. SSLv2 support allows cross-protocol attacks on TLS.",
        "mitigation": "Disable SSLv2 entirely. Ensure no SSLv2 support on any port.",
        "match": lambda tls: "SSLv2" in (tls.all_supported_protocols or []),
    },
    {
        "id": "CVE-2014-0160",
        "name": "Heartbleed",
        "severity": RiskLevel.CRITICAL,
        "description": "OpenSSL heartbeat extension buffer over-read. Allows extraction of server memory including private keys.",
        "mitigation": "Update OpenSSL to 1.0.1g+ or disable heartbeat extension.",
        "match": lambda tls: False,  # Cannot detect remotely without exploit — included for awareness
    },
    # ── Cipher weaknesses ──
    {
        "id": "CVE-2016-6329",
        "name": "Sweet32 (3DES Birthday Attack)",
        "severity": RiskLevel.MEDIUM,
        "description": "Birthday attack on 64-bit block ciphers (3DES/Blowfish) allows plaintext recovery after ~2^36 blocks.",
        "mitigation": "Disable 3DES cipher suites. Use AES-128 or AES-256.",
        "match": lambda tls: any(
            any(tok in c.get("name", "").upper() for tok in ["3DES", "DES-CBC3", "DES_CBC3"])
            for c in (tls.all_supported_ciphers or [])
        ),
    },
    {
        "id": "CVE-2017-9798",
        "name": "NULL Cipher Use",
        "severity": RiskLevel.CRITICAL,
        "description": "NULL ciphers provide no encryption — traffic is sent in plaintext.",
        "mitigation": "Remove all NULL cipher suites from TLS configuration.",
        "match": lambda tls: any("NULL" in c.get("name", "").upper() for c in (tls.all_supported_ciphers or [])),
    },
    # ── Key exchange weaknesses ──
    {
        "id": "QUANTUM-001",
        "name": "Harvest Now, Decrypt Later (HNDL)",
        "severity": RiskLevel.HIGH,
        "description": (
            "RSA/ECDH key exchange is vulnerable to Shor's algorithm. "
            "Adversaries may record encrypted traffic today and decrypt it "
            "when quantum computers become available (estimated 2030-2035)."
        ),
        "mitigation": "Adopt hybrid PQ key exchange (X25519Kyber768). Deploy CRYSTALS-Kyber (ML-KEM).",
        "match": lambda tls: tls.key_exchange in ("RSA", "ECDHE", "ECDH", "DHE", "DH"),
    },
    # ── Forward secrecy ──
    {
        "id": "FS-001",
        "name": "No Forward Secrecy",
        "severity": RiskLevel.HIGH,
        "description": (
            "Server does not support forward secrecy. Compromise of the server's "
            "private key would allow decryption of all past TLS sessions."
        ),
        "mitigation": "Enable ECDHE or DHE cipher suites to provide perfect forward secrecy.",
        "match": lambda tls: not tls.supports_forward_secrecy and not tls.error,
    },
    # ── Certificate issues ──
    {
        "id": "CERT-001",
        "name": "Certificate Nearing Expiry",
        "severity": RiskLevel.MEDIUM,
        "description": "Certificate expires within 30 days. Expired certificates cause service disruption and security warnings.",
        "mitigation": "Renew the TLS certificate before expiry. Use automated renewal (Let's Encrypt / ACME).",
        "match": lambda tls: (
            tls.certificate and
            tls.certificate.days_until_expiry is not None and
            0 < tls.certificate.days_until_expiry <= 30
        ),
    },
    {
        "id": "CERT-002",
        "name": "Certificate Expired",
        "severity": RiskLevel.CRITICAL,
        "description": "The TLS certificate has expired. Browsers will reject the connection.",
        "mitigation": "Immediately renew the TLS certificate.",
        "match": lambda tls: (
            tls.certificate and
            tls.certificate.days_until_expiry is not None and
            tls.certificate.days_until_expiry <= 0
        ),
    },
    {
        "id": "CERT-003",
        "name": "Self-Signed Certificate",
        "severity": RiskLevel.HIGH,
        "description": "Certificate is self-signed. Browsers will not trust it, and it provides no identity assurance.",
        "mitigation": "Obtain a certificate from a trusted Certificate Authority (CA).",
        "match": lambda tls: tls.certificate and tls.certificate.is_self_signed,
    },
    {
        "id": "CERT-004",
        "name": "Weak Certificate Key Size",
        "severity": RiskLevel.HIGH,
        "description": "Certificate uses an RSA key smaller than 2048 bits, considered insecure.",
        "mitigation": "Reissue the certificate with at least 2048-bit RSA or 256-bit ECC key.",
        "match": lambda tls: (
            tls.certificate and
            tls.certificate.public_key_size is not None and
            tls.certificate.public_key_size < 2048
        ),
    },
    # ── Legacy protocol ──
    {
        "id": "PROTO-001",
        "name": "TLS 1.0 Supported",
        "severity": RiskLevel.HIGH,
        "description": "TLS 1.0 is deprecated (RFC 8996). Vulnerable to BEAST and other attacks.",
        "mitigation": "Disable TLS 1.0. Use TLS 1.2 as minimum, preferably TLS 1.3.",
        "match": lambda tls: "TLSv1" in (tls.all_supported_protocols or []) and "TLSv1" not in ("TLSv1.1", "TLSv1.2", "TLSv1.3"),
    },
    {
        "id": "PROTO-002",
        "name": "TLS 1.1 Supported",
        "severity": RiskLevel.MEDIUM,
        "description": "TLS 1.1 is deprecated (RFC 8996). Major browsers no longer support it.",
        "mitigation": "Disable TLS 1.1. Use TLS 1.2 as minimum.",
        "match": lambda tls: "TLSv1.1" in (tls.all_supported_protocols or []),
    },
]


def map_cves(tls_results: List[TLSInfo]) -> List[CVEFinding]:
    """
    Map scan results to known CVEs and attacks.

    Tests each TLS result against every CVE rule in the database.
    Deduplicates findings by CVE ID.
    """
    findings: List[CVEFinding] = []
    seen_ids: set = set()

    for tls_info in tls_results:
        if tls_info.error:
            continue

        for cve in CVE_DATABASE:
            if cve["id"] in seen_ids:
                continue

            try:
                if cve["match"](tls_info):
                    findings.append(CVEFinding(
                        cve_id=cve["id"],
                        name=cve["name"],
                        severity=cve["severity"],
                        affected_component=f"{tls_info.host}:{tls_info.port}",
                        description=cve["description"],
                        mitigation=cve["mitigation"],
                    ))
                    seen_ids.add(cve["id"])
            except Exception as e:
                logger.warning("CVE match error for %s: %s", cve["id"], e)

    findings.sort(
        key=lambda f: ["critical", "high", "medium", "low", "safe"].index(f.severity.value)
    )

    logger.info("CVE mapping complete — %d findings", len(findings))
    return findings
