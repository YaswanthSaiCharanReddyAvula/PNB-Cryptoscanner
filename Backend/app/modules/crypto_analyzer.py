"""
QuantumShield — Crypto Analyzer Module

Parses TLS scanner output, classifies every cryptographic component
by risk level and quantum vulnerability, and normalises the data
into CBOM-ready CryptoComponent objects.
"""

from typing import List

from app.db.models import (
    AlgorithmCategory,
    CryptoComponent,
    QuantumStatus,
    RiskLevel,
    TLSInfo,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Algorithm classification databases ───────────────────────────

WEAK_ALGORITHMS = {
    # Hash algorithms
    "md5":        {"risk": RiskLevel.CRITICAL, "category": AlgorithmCategory.HASH},
    "sha1":       {"risk": RiskLevel.HIGH,     "category": AlgorithmCategory.HASH},
    "sha-1":      {"risk": RiskLevel.HIGH,     "category": AlgorithmCategory.HASH},
    # Ciphers
    "rc4":        {"risk": RiskLevel.CRITICAL, "category": AlgorithmCategory.CIPHER},
    "des":        {"risk": RiskLevel.CRITICAL, "category": AlgorithmCategory.CIPHER},
    "3des":       {"risk": RiskLevel.HIGH,     "category": AlgorithmCategory.CIPHER},
    "des-cbc3":   {"risk": RiskLevel.HIGH,     "category": AlgorithmCategory.CIPHER},
    "rc2":        {"risk": RiskLevel.CRITICAL, "category": AlgorithmCategory.CIPHER},
    "null":       {"risk": RiskLevel.CRITICAL, "category": AlgorithmCategory.CIPHER},
    "export":     {"risk": RiskLevel.CRITICAL, "category": AlgorithmCategory.CIPHER},
}

# Algorithms vulnerable to quantum attacks (Shor's / Grover's)
QUANTUM_VULNERABLE_KX = {"RSA", "DH", "DHE", "ECDH", "ECDHE"}

QUANTUM_VULNERABLE_SIG = {
    "rsa", "ecdsa", "dsa",
    "sha256withrsa", "sha384withrsa", "sha512withrsa",
    "sha256withrsaencryption", "sha384withrsaencryption",
    "sha256withecdsa", "sha384withecdsa",
    "rsaencryption",
}

SAFE_PROTOCOLS = {"TLSv1.3", "TLSv1.2"}

_PQC_KX_HINTS = ("kyber", "ml-kem", "mlkem", "crystals", "pqtls", "kemtls")


def _primary_threat(category: AlgorithmCategory) -> str:
    """Map CBOM category to dominant quantum threat model."""
    if category in (AlgorithmCategory.KEY_EXCHANGE, AlgorithmCategory.SIGNATURE):
        return "shor"
    if category in (AlgorithmCategory.CIPHER, AlgorithmCategory.HASH):
        return "grover"
    return "hndl"  # protocol


def _tag_component(comp: CryptoComponent, host: str) -> CryptoComponent:
    return comp.model_copy(
        update={
            "host": host,
            "primary_quantum_threat": _primary_threat(comp.category),
        }
    )


def _classify_protocol(tls_version: str | None) -> CryptoComponent:
    """Assess the TLS protocol version."""
    version = tls_version or "UNKNOWN"
    if version in ("TLSv1.3",):
        risk = RiskLevel.SAFE
    elif version in ("TLSv1.2",):
        risk = RiskLevel.LOW
    elif version in ("TLSv1.1", "TLSv1"):
        risk = RiskLevel.HIGH
    else:
        risk = RiskLevel.CRITICAL  # SSLv3, SSLv2, unknown

    return CryptoComponent(
        name=version,
        category=AlgorithmCategory.PROTOCOL,
        usage_context="TLS protocol version",
        risk_level=risk,
        quantum_status=QuantumStatus.QUANTUM_SAFE,  # protocols themselves aren't quantum-broken
        details=f"Negotiated protocol: {version}",
    )


def _classify_cipher(cipher_suite: str | None, bits: int | None) -> CryptoComponent:
    """Assess the symmetric cipher from the negotiated suite."""
    name = cipher_suite or "UNKNOWN"
    name_lower = name.lower()

    risk = RiskLevel.SAFE
    for weak_token, info in WEAK_ALGORITHMS.items():
        if weak_token in name_lower:
            risk = info["risk"]
            break

    if bits and bits < 128:
        risk = max(risk, RiskLevel.HIGH, key=lambda r: list(RiskLevel).index(r))

    return CryptoComponent(
        name=name,
        category=AlgorithmCategory.CIPHER,
        key_size=bits,
        usage_context="Negotiated cipher suite",
        risk_level=risk,
        quantum_status=QuantumStatus.PARTIALLY_SAFE,  # symmetric ciphers need 2x key size for Grover's
        details=f"Cipher bits: {bits}",
    )


def _classify_key_exchange(kx: str | None) -> CryptoComponent:
    """Assess the key-exchange algorithm."""
    name = kx or "UNKNOWN"
    name_l = name.lower()
    pqc_hint = any(h in name_l for h in _PQC_KX_HINTS)
    quantum = (
        QuantumStatus.QUANTUM_SAFE
        if pqc_hint
        else (
            QuantumStatus.VULNERABLE if name.upper() in QUANTUM_VULNERABLE_KX else QuantumStatus.QUANTUM_SAFE
        )
    )

    if name.upper() in ("RSA",):
        risk = RiskLevel.HIGH  # Static RSA key exchange — no forward secrecy
    elif name.upper() in ("DH",):
        risk = RiskLevel.MEDIUM
    else:
        risk = RiskLevel.SAFE  # ephemeral variants are fine classically

    return CryptoComponent(
        name=name,
        category=AlgorithmCategory.KEY_EXCHANGE,
        usage_context="TLS key exchange",
        risk_level=risk,
        quantum_status=quantum,
        details=(
            "PQC/hybrid KEM signal in name (verify deployment)"
            if pqc_hint
            else ("Quantum-vulnerable" if quantum == QuantumStatus.VULNERABLE else "Classically secure")
        ),
    )


def _classify_signature_and_hash(
    sig_alg: str | None,
    key_size: int | None,
    *,
    hash_usage_context: str = "Certificate signature hash",
    sig_usage_context: str = "Certificate public key algorithm",
) -> List[CryptoComponent]:
    """Assess the certificate's signature and embedded hash algorithms."""
    name = sig_alg or "UNKNOWN"
    name_lower = name.lower().replace("-", "").replace("_", "")
    components = []

    # Extract Hash if present
    hash_alg = None
    if "md5" in name_lower:
        hash_alg = "MD5"
    elif "sha1" in name_lower:
        hash_alg = "SHA-1"
    elif "sha256" in name_lower:
        hash_alg = "SHA-256"
    elif "sha384" in name_lower:
        hash_alg = "SHA-384"
    elif "sha512" in name_lower:
        hash_alg = "SHA-512"

    if hash_alg:
        hash_risk = RiskLevel.SAFE
        if hash_alg in ["MD5", "SHA-1"]:
            hash_risk = RiskLevel.CRITICAL
            
        components.append(CryptoComponent(
            name=hash_alg,
            category=AlgorithmCategory.HASH,
            usage_context=hash_usage_context,
            risk_level=hash_risk,
            quantum_status=QuantumStatus.QUANTUM_SAFE if hash_alg not in ["MD5", "SHA-1"] else QuantumStatus.VULNERABLE,
        ))

    # Determine Base Signature Algorithm
    base_sig = "Unknown"
    if "rsa" in name_lower:
        base_sig = "RSA"
    elif "ecdsa" in name_lower:
        base_sig = "ECDSA"
    elif "dsa" in name_lower:
        base_sig = "DSA"
    else:
        base_sig = name

    quantum = (
        QuantumStatus.VULNERABLE
        if any(vuln in name_lower for vuln in QUANTUM_VULNERABLE_SIG)
        else QuantumStatus.QUANTUM_SAFE
    )

    sig_risk = RiskLevel.SAFE
    if key_size and key_size < 2048:
        sig_risk = RiskLevel.HIGH

    components.append(CryptoComponent(
        name=base_sig,
        category=AlgorithmCategory.SIGNATURE,
        key_size=key_size,
        usage_context=sig_usage_context,
        risk_level=sig_risk,
        quantum_status=quantum,
    ))

    return components


def analyze(tls_info: TLSInfo) -> List[CryptoComponent]:
    """
    Analyse a single TLS scan result and return classified crypto components.

    Extracts components from:
      1. Negotiated protocol version
      2. Negotiated cipher suite
      3. Negotiated key exchange
      4. Certificate signature algorithm
      5. ALL supported protocol versions (enhanced)
      6. ALL supported cipher suites (enhanced)
    """
    if tls_info.error:
        logger.warning("Skipping analysis for %s:%d — scan error.", tls_info.host, tls_info.port)
        return []

    logger.info("Analysing crypto for %s:%d ...", tls_info.host, tls_info.port)

    components: List[CryptoComponent] = [
        _classify_protocol(tls_info.tls_version),
        _classify_cipher(tls_info.cipher_suite, tls_info.cipher_bits),
        _classify_key_exchange(tls_info.key_exchange),
    ]

    if tls_info.certificate:
        components.extend(
            _classify_signature_and_hash(
                tls_info.certificate.signature_algorithm,
                tls_info.certificate.public_key_size,
                hash_usage_context="Leaf certificate signature hash",
                sig_usage_context="Leaf certificate public key algorithm",
            )
        )

    # Full chain: intermediates / root may use weaker hashes or RSA sizes
    for entry in tls_info.cert_chain or []:
        if getattr(entry, "error", None):
            continue
        if not entry.signature_algorithm:
            continue
        d = int(entry.depth) if entry.depth is not None else 0
        components.extend(
            _classify_signature_and_hash(
                entry.signature_algorithm,
                entry.public_key_size,
                hash_usage_context=f"Certificate chain depth {d} signature hash",
                sig_usage_context=f"Certificate chain depth {d} public key algorithm",
            )
        )

    # ── Enhanced: classify ALL supported protocols ──
    seen_protocols = {tls_info.tls_version}
    for proto in tls_info.all_supported_protocols:
        if proto not in seen_protocols:
            components.append(_classify_protocol(proto))
            seen_protocols.add(proto)

    # ── Enhanced: classify ALL supported cipher suites ──
    seen_ciphers = {tls_info.cipher_suite}
    for cipher in tls_info.all_supported_ciphers:
        cipher_name = cipher.get("name")
        if cipher_name and cipher_name not in seen_ciphers:
            components.append(_classify_cipher(cipher_name, cipher.get("bits")))
            seen_ciphers.add(cipher_name)

    tagged = [_tag_component(c, tls_info.host) for c in components]

    logger.info(
        "Crypto analysis complete for %s:%d — %d components, highest risk: %s",
        tls_info.host,
        tls_info.port,
        len(tagged),
        max(c.risk_level for c in tagged) if tagged else "N/A",
    )
    return tagged
