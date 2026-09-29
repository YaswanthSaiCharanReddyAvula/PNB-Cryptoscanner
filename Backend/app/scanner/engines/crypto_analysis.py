"""
QuantumShield — Crypto Analysis Engine (Stage 5)

Pure-Python analysis of TLS profiles produced by Stage 4.  Classifies every
cryptographic primitive against a quantum-risk taxonomy and detects Harvest
Now Decrypt Later (HNDL) exposure.
"""

from __future__ import annotations

import re
from typing import Any

from app.scanner.models import (
    CertificateDetail,
    CipherDetail,
    CryptoFinding,
    StageResult,
    TLSProfile,
)
from app.scanner.pipeline import MergeStrategy, ScanContext, ScanStage, StageCriticality
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── Algorithm → quantum-risk taxonomy ────────────────────────────────────

ALGORITHM_RISK_MAP: dict[str, dict[str, Any]] = {
    # Key exchange
    "RSA": {
        "quantum_risk": "high",
        "threat": "Shor's algorithm factors RSA moduli in polynomial time",
        "hndl_risk": True,
        "recommendation": "ML-KEM (FIPS 203)",
    },
    "ECDHE": {
        "quantum_risk": "high",
        "threat": "Shor's algorithm solves ECDLP",
        "hndl_risk": True,
        "recommendation": "ML-KEM (FIPS 203)",
    },
    "ECDH": {
        "quantum_risk": "high",
        "threat": "Shor's algorithm solves ECDLP",
        "hndl_risk": True,
        "recommendation": "ML-KEM (FIPS 203)",
    },
    "DHE": {
        "quantum_risk": "high",
        "threat": "Shor's algorithm solves DLP",
        "hndl_risk": True,
        "recommendation": "ML-KEM (FIPS 203)",
    },
    "DH": {
        "quantum_risk": "high",
        "threat": "Shor's algorithm solves DLP",
        "hndl_risk": True,
        "recommendation": "ML-KEM (FIPS 203)",
    },
    "RSA_EXPORT": {
        "quantum_risk": "critical",
        "threat": "Export-grade key + Shor's algorithm",
        "hndl_risk": True,
        "recommendation": "ML-KEM (FIPS 203)",
    },
    
    # Generic EC Key type when usage (ECDSA vs ECDH) cannot be resolved strictly from "EC" label
    "EC": {
        "quantum_risk": "high",
        "threat": "Shor's algorithm solves ECDLP",
        "hndl_risk": False,  # We don't assume HNDL for a generic cert key, HNDL comes from KEX
        "recommendation": "ML-DSA / ML-KEM",
    },

    # Authentication
    "ECDSA": {
        "quantum_risk": "high",
        "threat": "Shor's algorithm solves ECDLP",
        "hndl_risk": False,
        "recommendation": "ML-DSA (FIPS 204)",
    },
    "DSA": {
        "quantum_risk": "high",
        "threat": "Shor's algorithm solves DLP",
        "hndl_risk": False,
        "recommendation": "ML-DSA (FIPS 204)",
    },
    "EDDSA": {
        "quantum_risk": "high",
        "threat": "Shor's algorithm solves ECDLP",
        "hndl_risk": False,
        "recommendation": "ML-DSA (FIPS 204)",
    },
    "ED25519": {
        "quantum_risk": "high",
        "threat": "Shor's algorithm solves ECDLP",
        "hndl_risk": False,
        "recommendation": "ML-DSA (FIPS 204)",
    },
    "ED448": {
        "quantum_risk": "high",
        "threat": "Shor's algorithm solves ECDLP",
        "hndl_risk": False,
        "recommendation": "ML-DSA (FIPS 204)",
    },
    "RSA-PSS": {
        "quantum_risk": "high",
        "threat": "Shor's algorithm factors RSA moduli in polynomial time",
        "hndl_risk": False,
        "recommendation": "ML-DSA (FIPS 204)",
    },

    # Symmetric encryption
    "AES-128": {
        "quantum_risk": "medium",
        "threat": "Grover halves effective key length to 64-bit",
        "hndl_risk": False,
        "recommendation": "AES-256 for post-quantum margin",
    },
    "AES-256": {
        "quantum_risk": "low",
        "threat": "Grover reduces to 128-bit — still secure",
        "hndl_risk": False,
        "recommendation": "Sufficient post-quantum strength",
    },
    "CHACHA20": {
        "quantum_risk": "low",
        "threat": "Grover reduces to 128-bit — still secure",
        "hndl_risk": False,
        "recommendation": "Sufficient post-quantum strength",
    },
    "3DES": {
        "quantum_risk": "critical",
        "threat": "Grover + classical Sweet32 attack",
        "hndl_risk": False,
        "recommendation": "Migrate to AES-256-GCM",
    },
    "DES": {
        "quantum_risk": "critical",
        "threat": "Classical brute-force + Grover",
        "hndl_risk": False,
        "recommendation": "Migrate to AES-256-GCM",
    },
    "RC4": {
        "quantum_risk": "critical",
        "threat": "Classical statistical biases (fully broken)",
        "hndl_risk": False,
        "recommendation": "Migrate to AES-256-GCM",
    },
    "NULL": {
        "quantum_risk": "critical",
        "threat": "No encryption — plaintext exposure",
        "hndl_risk": False,
        "recommendation": "Enable authenticated encryption",
    },

    # Hash / MAC
    "MD5": {
        "quantum_risk": "critical",
        "threat": "Classical collision attacks (fully broken)",
        "hndl_risk": False,
        "recommendation": "SHA-256 or SHA-384",
    },
    "SHA-1": {
        "quantum_risk": "high",
        "threat": "Classical collision attacks + Grover",
        "hndl_risk": False,
        "recommendation": "SHA-256 or SHA-384",
    },
    "SHA-256": {
        "quantum_risk": "medium",
        "threat": "Grover halves preimage resistance",
        "hndl_risk": False,
        "recommendation": "SHA-384 for long-term security",
    },
    "SHA-384": {
        "quantum_risk": "low",
        "threat": "Grover (mitigated by 384-bit output)",
        "hndl_risk": False,
        "recommendation": "Sufficient post-quantum strength",
    },
    "SHA-512": {
        "quantum_risk": "low",
        "threat": "Grover (mitigated by 512-bit output)",
        "hndl_risk": False,
        "recommendation": "Sufficient post-quantum strength",
    },
    "SHA-3": {
        "quantum_risk": "low",
        "threat": "Grover (mitigated by output size)",
        "hndl_risk": False,
        "recommendation": "Sufficient post-quantum strength",
    },

    # Post-quantum algorithms (quantum-safe)
    "ML-KEM": {
        "quantum_risk": "none",
        "threat": "none",
        "hndl_risk": False,
        "recommendation": "FIPS 203 approved",
        "pqc": True,
    },
    "KYBER": {
        "quantum_risk": "none",
        "threat": "none",
        "hndl_risk": False,
        "recommendation": "FIPS 203 approved",
        "pqc": True,
    },
    "ML-DSA": {
        "quantum_risk": "none",
        "threat": "none",
        "hndl_risk": False,
        "recommendation": "FIPS 204 approved",
        "pqc": True,
    },
    "DILITHIUM": {
        "quantum_risk": "none",
        "threat": "none",
        "hndl_risk": False,
        "recommendation": "FIPS 204 approved",
        "pqc": True,
    },
    "X25519KYBER": {
        "quantum_risk": "none",
        "threat": "none",
        "hndl_risk": False,
        "recommendation": "Hybrid PQC key exchange",
        "pqc": True,
    },
    "SECP256R1MLKEM": {
        "quantum_risk": "none",
        "threat": "none",
        "hndl_risk": False,
        "recommendation": "Hybrid PQC key exchange",
        "pqc": True,
    },
}

_RISK_PENALTY: dict[str, int] = {
    "critical": 20,
    "high": 12,
    "medium": 5,
    "low": 2,
    "none": 0,
}

_CLASSICAL_KEX = frozenset({"RSA", "ECDHE", "ECDH", "DHE", "DH", "RSA_EXPORT"})


class CryptoAnalysisEngine(ScanStage):
    """Stage 5 — Classify every crypto primitive against the quantum-risk map."""

    name = "crypto_analysis"
    order = 5
    timeout_seconds = 30
    criticality = StageCriticality.IMPORTANT
    required_fields: list[str] = []  # runs even with partial TLS data
    writes_fields = ["crypto_findings"]
    merge_strategy = MergeStrategy.OVERWRITE

    # ── risk-map lookup ──────────────────────────────────────────────

    @staticmethod
    def _canonicalize_alg(algorithm: str) -> str:
        """Deterministically canonicalize algorithm identifiers."""
        alg = algorithm.upper().strip()
        # Explicit aliases
        aliases = {
            "SHA1": "SHA-1",
            "SHA256": "SHA-256",
            "SHA384": "SHA-384",
            "SHA512": "SHA-512",
            "SHA3": "SHA-3",
        }
        return aliases.get(alg, alg)

    @staticmethod
    def _match_risk(algorithm: str) -> dict[str, Any] | None:
        """Exact matching using canonical identifiers to prevent substring false-positives."""
        if not algorithm:
            return None
        canon = CryptoAnalysisEngine._canonicalize_alg(algorithm)
        if canon in ALGORITHM_RISK_MAP:
            return ALGORITHM_RISK_MAP[canon]
        return None

    @staticmethod
    def _extract_sig_hash(sig_alg: str) -> str | None:
        """Pull the hash component out of a signature algorithm OID name."""
        low = sig_alg.lower()
        for token, label in (
            ("sha512", "SHA-512"),
            ("sha384", "SHA-384"),
            ("sha256", "SHA-256"),
            ("sha1", "SHA-1"),
            ("md5", "MD5"),
        ):
            if token in low:
                return label
        return None

    # ── 1. classify cipher suite components ──────────────────────────

    def _classify_cipher(
        self, host: str, port: int, cipher: CipherDetail,
    ) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []

        # Key exchange (skip TLS 1.3 placeholder)
        kex = cipher.kex or ""
        if kex and kex != "any (TLS 1.3)":
            risk = self._match_risk(kex)
            if risk and risk["quantum_risk"] not in ("none", "low"):
                findings.append(CryptoFinding(
                    host=host,
                    port=port,
                    component="cipher_kex",
                    algorithm=kex,
                    quantum_risk=risk["quantum_risk"],
                    threat_vector=risk["threat"],
                    hndl_risk="yes" if risk.get("hndl_risk") else "no",
                    nist_recommendation=risk.get("recommendation", ""),
                    evidence=f"Cipher {cipher.name} uses {kex} key exchange",
                    confidence="high",
                ))

        # Encryption
        enc = cipher.encryption or ""
        if enc:
            risk = self._match_risk(enc)
            if risk and risk["quantum_risk"] != "none":
                findings.append(CryptoFinding(
                    host=host,
                    port=port,
                    component="cipher_enc",
                    algorithm=enc,
                    quantum_risk=risk["quantum_risk"],
                    threat_vector=risk["threat"],
                    hndl_risk="no",
                    nist_recommendation=risk.get("recommendation", ""),
                    evidence=(
                        f"Cipher {cipher.name} uses {enc} "
                        f"({cipher.bits or '?'}-bit) encryption"
                    ),
                    confidence="high",
                ))

        # MAC (AEAD is not a standalone hash — skip)
        mac = cipher.mac or ""
        if mac and mac.upper() != "AEAD":
            risk = self._match_risk(mac)
            if risk and risk["quantum_risk"] != "none":
                findings.append(CryptoFinding(
                    host=host,
                    port=port,
                    component="cipher_mac",
                    algorithm=mac,
                    quantum_risk=risk["quantum_risk"],
                    threat_vector=risk["threat"],
                    hndl_risk="no",
                    nist_recommendation=risk.get("recommendation", ""),
                    evidence=f"Cipher {cipher.name} uses {mac} MAC",
                    confidence="high",
                ))

        # Forward Secrecy Explicit Finding
        if cipher.pfs is not None:
            if not cipher.pfs:
                findings.append(CryptoFinding(
                    host=host,
                    port=port,
                    component="forward_secrecy",
                    algorithm="no_pfs",
                    quantum_risk="high",
                    threat_vector="Classically vulnerable to key compromise; HNDL exposure",
                    hndl_risk="yes",
                    nist_recommendation="Enable ECDHE or DHE for Perfect Forward Secrecy",
                    evidence=f"Cipher {cipher.name} does not provide Perfect Forward Secrecy",
                    confidence="high",
                ))

        return findings

    # ── 2. classify certificate crypto ───────────────────────────────

    def _classify_cert(
        self, host: str, port: int, cert: CertificateDetail, position: str = "leaf"
    ) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []

        # Public-key algorithm
        if cert.key_type:
            risk = self._match_risk(cert.key_type)
            if risk:
                label = (
                    f"{cert.key_type}-{cert.key_size}"
                    if cert.key_size
                    else cert.key_type
                )
                findings.append(CryptoFinding(
                    host=host,
                    port=port,
                    component=f"certificate_key_{position}",
                    algorithm=label,
                    quantum_risk=risk["quantum_risk"],
                    threat_vector=risk["threat"],
                    hndl_risk="no",
                    nist_recommendation=risk.get("recommendation", ""),
                    evidence=(
                        f"{position.capitalize()} certificate uses {cert.key_type} "
                        f"{cert.key_size or '?'}-bit key"
                    ),
                    confidence="high",
                ))

        # Undersized RSA key
        if cert.key_type == "RSA" and cert.key_size and cert.key_size < 2048:
            findings.append(CryptoFinding(
                host=host,
                port=port,
                component=f"certificate_key_{position}",
                algorithm=f"RSA-{cert.key_size}",
                quantum_risk="critical",
                threat_vector=(
                    "RSA key below 2048-bit minimum — "
                    "classical and quantum vulnerable"
                ),
                hndl_risk="yes",
                nist_recommendation="Minimum 2048-bit RSA or migrate to ML-DSA",
                evidence=(
                    f"RSA key size {cert.key_size} bits in {position} certificate "
                    f"is below the 2048-bit minimum"
                ),
                confidence="high",
            ))

        # Signature hash
        if cert.sig_algorithm:
            hash_name = self._extract_sig_hash(cert.sig_algorithm)
            if hash_name:
                risk = self._match_risk(hash_name)
                if risk and risk["quantum_risk"] not in ("none", "low"):
                    findings.append(CryptoFinding(
                        host=host,
                        port=port,
                        component=f"cert_signature_{position}",
                        algorithm=hash_name,
                        quantum_risk=risk["quantum_risk"],
                        threat_vector=risk["threat"],
                        hndl_risk="no",
                        nist_recommendation=risk.get("recommendation", ""),
                        evidence=(
                            f"{position.capitalize()} certificate signed with {cert.sig_algorithm} "
                            f"(hash: {hash_name})"
                        ),
                        confidence="high",
                    ))

        # Validity / Trust evaluation on the leaf certificate explicitly
        if position == "leaf":
            if cert.expired:
                findings.append(CryptoFinding(
                    host=host,
                    port=port,
                    component="certificate_validity",
                    algorithm="expired",
                    quantum_risk="critical",
                    threat_vector="Expired certificate — trust chain broken",
                    hndl_risk="no",
                    nist_recommendation="Renew certificate immediately",
                    evidence=(
                        f"Certificate expired "
                        f"{abs(cert.days_until_expiry or 0)} days ago"
                    ),
                    confidence="high",
                ))
            elif cert.days_until_expiry is not None and cert.days_until_expiry < 30:
                findings.append(CryptoFinding(
                    host=host,
                    port=port,
                    component="certificate_validity",
                    algorithm="expiring_soon",
                    quantum_risk="low",
                    threat_vector="Certificate approaching expiry",
                    hndl_risk="no",
                    nist_recommendation="Renew certificate before expiry",
                    evidence=f"Certificate expires in {cert.days_until_expiry} days",
                    confidence="high",
                ))

            if cert.is_self_signed:
                findings.append(CryptoFinding(
                    host=host,
                    port=port,
                    component="certificate_trust",
                    algorithm="self_signed",
                    quantum_risk="medium",
                    threat_vector="Self-signed — no third-party CA trust chain",
                    hndl_risk="no",
                    nist_recommendation="Use a CA-signed certificate",
                    evidence="Certificate is self-signed",
                    confidence="high",
                ))

        return findings

    # ── 3. classify protocol versions ────────────────────────────────

    def _classify_protocol(
        self, host: str, port: int, versions: dict[str, bool],
    ) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []

        if versions.get("TLSv1"):
            findings.append(CryptoFinding(
                host=host,
                port=port,
                component="protocol",
                algorithm="TLS 1.0",
                quantum_risk="high",
                threat_vector="Deprecated — POODLE, BEAST, classical weaknesses",
                hndl_risk="yes",
                nist_recommendation="Disable TLS 1.0; require TLS 1.2+",
                evidence="TLS 1.0 is enabled",
                confidence="high",
            ))

        if versions.get("TLSv1_1"):
            findings.append(CryptoFinding(
                host=host,
                port=port,
                component="protocol",
                algorithm="TLS 1.1",
                quantum_risk="high",
                threat_vector="Deprecated — classical weaknesses",
                hndl_risk="yes",
                nist_recommendation="Disable TLS 1.1; require TLS 1.2+",
                evidence="TLS 1.1 is enabled",
                confidence="high",
            ))

        has_12 = versions.get("TLSv1_2", False)
        has_13 = versions.get("TLSv1_3", False)

        if not has_12 and not has_13:
            findings.append(CryptoFinding(
                host=host,
                port=port,
                component="protocol",
                algorithm="no_modern_tls",
                quantum_risk="critical",
                threat_vector="No modern TLS version available",
                hndl_risk="yes",
                nist_recommendation="Enable TLS 1.2 and TLS 1.3",
                evidence="Neither TLS 1.2 nor TLS 1.3 is supported",
                confidence="high",
            ))

        if not has_13:
            findings.append(CryptoFinding(
                host=host,
                port=port,
                component="protocol",
                algorithm="no_tls_1.3",
                quantum_risk="medium",
                threat_vector="TLS 1.3 absent — missing PQC transition readiness",
                hndl_risk="no",
                nist_recommendation="Enable TLS 1.3 for PQC readiness",
                evidence="TLS 1.3 is not supported",
                confidence="medium",
            ))

        return findings

    # ── 4. assess Harvest Now Decrypt Later risk ─────────────────────

    def _assess_hndl(
        self, host: str, port: int, profile: TLSProfile,
    ) -> list[CryptoFinding]:
        # Identify KEX that were ACTUALLY negotiated (not merely advertised supported ciphers)
        # If no negotiated KEX is present, we must rely on accepted ciphers.
        
        negotiated_kex = None
        if profile.negotiated_cipher:
            for c in profile.accepted_ciphers:
                if c.name == profile.negotiated_cipher:
                    negotiated_kex = c.kex
                    break
                    
        # Check PQC Signals: Distinguish "negotiated" from "advertised"
        # We only suppress HNDL if a PQC algorithm was truly NEGOTIATED.
        pqc_negotiated = False
        
        # Check if any negotiated cipher indicates PQC
        if profile.negotiated_cipher and any(ind in profile.negotiated_cipher.upper() for ind in ["KYBER", "MLKEM", "ML-KEM"]):
            pqc_negotiated = True
            
        # Check explicit pqc_signals flag for the prefix "negotiated:"
        if profile.pqc_signals:
            for sig in profile.pqc_signals:
                if sig.startswith("negotiated:"):
                    pqc_negotiated = True
                    break
        
        # If PQC key exchange was successfully negotiated, there is no HNDL risk for the active connection.
        if pqc_negotiated:
            return []
            
        # Determine if classical algorithms are used
        has_classical_kex = False
        if negotiated_kex and negotiated_kex.upper() in _CLASSICAL_KEX:
            has_classical_kex = True
        elif not negotiated_kex and any((c.kex or "").upper() in _CLASSICAL_KEX for c in profile.accepted_ciphers):
            has_classical_kex = True
            
        if not has_classical_kex and not profile.negotiated_cipher:
            return []

        if not has_classical_kex:
            has_classical_kex = True

        return [CryptoFinding(
            host=host,
            port=port,
            component="hndl_risk",
            algorithm="classical_kex_only",
            quantum_risk="high",
            threat_vector=(
                "Harvest Now Decrypt Later — encrypted traffic can be "
                "stored and decrypted by future quantum computers"
            ),
            hndl_risk="yes",
            nist_recommendation=(
                "Deploy hybrid PQC key exchange (ML-KEM + classical)"
            ),
            evidence=(
                f"No PQC key exchange negotiated for {host}:{port}; "
                f"session uses quantum-vulnerable classical algorithms"
            ),
            confidence="high",
        )]

    # ── 5. compute per-host crypto readiness score ───────────────────

    @staticmethod
    def _compute_host_crypto_score(findings: list[CryptoFinding]) -> int:
        """Score 0–100.  Start at 100, deduct per unique finding by risk."""
        score = 100
        seen: set[tuple[str, str]] = set()
        for f in findings:
            key = (f.component, f.algorithm)
            if key in seen:
                continue
            seen.add(key)
            score -= _RISK_PENALTY.get(f.quantum_risk, 5)
        return max(0, min(100, score))

    # ── execute (pipeline entry-point) ───────────────────────────────

    async def execute(self, ctx: ScanContext) -> StageResult:
        all_findings: list[dict] = []

        for raw in (ctx.tls_profiles or []):
            try:
                profile = (
                    TLSProfile(**raw) if isinstance(raw, dict) else raw
                )
            except Exception as exc:
                logger.warning("Skipping invalid TLS profile: %s", exc)
                continue

            host, port = profile.host, profile.port
            findings: list[CryptoFinding] = []

            for cipher in profile.accepted_ciphers:
                findings.extend(self._classify_cipher(host, port, cipher))

            # Analyze full certificate chain (C-01 Fix)
            if profile.cert_chain:
                for i, cert in enumerate(profile.cert_chain):
                    pos = "leaf" if i == 0 else f"intermediate_{i}"
                    findings.extend(self._classify_cert(host, port, cert, position=pos))
            elif profile.leaf_cert:
                # Fallback if only leaf is populated
                findings.extend(self._classify_cert(host, port, profile.leaf_cert, position="leaf"))

            findings.extend(
                self._classify_protocol(host, port, profile.tls_versions_supported),
            )

            findings.extend(self._assess_hndl(host, port, profile))

            score = self._compute_host_crypto_score(findings)
            findings.append(CryptoFinding(
                host=host,
                port=port,
                component="crypto_score",
                algorithm="composite",
                quantum_risk="info",
                evidence=f"Host crypto-quantum readiness score: {score}/100",
                confidence="high",
            ))

            all_findings.extend(f.model_dump() for f in findings)

        return StageResult(
            status="completed",
            data={"crypto_findings": all_findings},
        )
