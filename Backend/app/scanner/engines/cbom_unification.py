"""
QuantumShield — CBOM Unification Engine (Track C, Stage 14 + 15)

The "CBOM Brain" — aggregates data from Track A (runtime/external) and
Track B (build/internal), applies deduplication, normalization, and
generates the CERT-IN / PNB Annexure-A compliant Cryptographic Bill of
Materials in strict JSON schema.

Extraction logic:
  A.  Protocols & Cipher Suites  →  from TLS probes + host configs
  B.  Certificates               →  from public TLS + internal .pem/.crt
  C.  Algorithms                  →  from network ciphers + SAST analysis
  D.  Keys                        →  SHA-256 fingerprints of all discovered keys
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from app.scanner.models import (
    CBOMAlgorithm,
    CBOMCertificate,
    CBOMKey,
    CBOMMetadata,
    CBOMProtocol,
    CBOMReport,
    StageResult,
)
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── OID mapping for common signature algorithms ──────────────────────

_SIG_ALG_OID_MAP: dict[str, str] = {
    "sha256WithRSAEncryption":    "1.2.840.113549.1.1.11",
    "sha384WithRSAEncryption":    "1.2.840.113549.1.1.12",
    "sha512WithRSAEncryption":    "1.2.840.113549.1.1.13",
    "sha1WithRSAEncryption":      "1.2.840.113549.1.1.5",
    "md5WithRSAEncryption":       "1.2.840.113549.1.1.4",
    "ecdsa-with-SHA256":          "1.2.840.10045.4.3.2",
    "ecdsa-with-SHA384":          "1.2.840.10045.4.3.3",
    "ecdsa-with-SHA512":          "1.2.840.10045.4.3.4",
    # OID dotted string fallbacks
    "1.2.840.113549.1.1.11":      "1.2.840.113549.1.1.11",
    "1.2.840.113549.1.1.12":      "1.2.840.113549.1.1.12",
    "1.2.840.113549.1.1.13":      "1.2.840.113549.1.1.13",
}

_SIG_ALG_HUMAN: dict[str, str] = {
    "1.2.840.113549.1.1.11": "sha256WithRSA",
    "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA",
    "1.2.840.113549.1.1.5":  "sha1WithRSA",
    "1.2.840.113549.1.1.4":  "md5WithRSA",
    "1.2.840.10045.4.3.2":   "ecdsaWithSHA256",
    "1.2.840.10045.4.3.3":   "ecdsaWithSHA384",
    "1.2.840.10045.4.3.4":   "ecdsaWithSHA512",
}

# ── Primitive classification ─────────────────────────────────────────

_PRIMITIVE_MAP: dict[str, str] = {
    "AES":       "symmetric encryption",
    "CHACHA20":  "symmetric encryption",
    "CAMELLIA":  "symmetric encryption",
    "3DES":      "symmetric encryption",
    "DES":       "symmetric encryption",
    "RC4":       "symmetric encryption",
    "ARIA":      "symmetric encryption",
    "RSA":       "signature",
    "ECDSA":     "signature",
    "ECDHE":     "key_agreement",
    "ECDH":      "key_agreement",
    "DHE":       "key_agreement",
    "DH":        "key_agreement",
    "SHA256":    "hash",
    "SHA-256":   "hash",
    "SHA384":    "hash",
    "SHA-384":   "hash",
    "SHA512":    "hash",
    "SHA-512":   "hash",
    "SHA1":      "hash",
    "SHA-1":     "hash",
    "MD5":       "hash",
    "BCRYPT":    "hash",
    "ARGON2":    "hash",
    "PBKDF2":    "hash",
    "SCRYPT":    "hash",
    "BLAKE2":    "hash",
    "ML-KEM":    "key_agreement",
    "KYBER":     "key_agreement",
    "ML-DSA":    "signature",
    "DILITHIUM": "signature",
}

# ── Mode tokens ──────────────────────────────────────────────────────

_MODE_TOKENS = ("GCM", "CBC", "CCM", "CTR", "ECB", "CFB", "OFB", "POLY1305", "XTS")


def _classify_primitive(name: str) -> str:
    """Map an algorithm name to its primitive type."""
    upper = name.upper().replace("-", "").replace("_", "")
    for token, prim in _PRIMITIVE_MAP.items():
        if token.upper().replace("-", "") in upper:
            return prim
    return "unknown"


def _extract_mode(name: str) -> str:
    """Extract the operational mode from an algorithm/cipher name."""
    upper = name.upper()
    for mode in _MODE_TOKENS:
        if mode in upper:
            return mode
    return "N/A"


def _extract_bits(name: str) -> int | None:
    """Pull bit-size from a name like 'AES-256-GCM' or 'RSA-2048'."""
    nums = re.findall(r"\d+", name)
    for n in nums:
        val = int(n)
        if val in (64, 128, 192, 256, 384, 512, 1024, 2048, 3072, 4096, 521):
            return val
    return None


def _classical_security_level(primitive: str, bits: int) -> int:
    """Compute classical security level in bits per the architecture spec."""
    prim_lower = primitive.lower()
    if "symmetric" in prim_lower:
        return bits
    if "hash" in prim_lower:
        return bits
    if "rsa" in prim_lower or "signature" in prim_lower:
        rsa_map = {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192}
        return rsa_map.get(bits, 112)
    if "key_agreement" in prim_lower or "ecc" in prim_lower:
        ecc_map = {256: 128, 384: 192, 521: 256}
        return ecc_map.get(bits, bits // 2)
    return bits


def _resolve_sig_oid(sig_alg: str | None) -> str:
    """Resolve a signature algorithm string to its OID + human-readable label."""
    if not sig_alg:
        return "unknown"
    # Already an OID?
    if sig_alg.startswith("1."):
        human = _SIG_ALG_HUMAN.get(sig_alg, sig_alg)
        return f"{sig_alg} ({human})"
    # Name → OID
    oid = _SIG_ALG_OID_MAP.get(sig_alg)
    if oid:
        human = _SIG_ALG_HUMAN.get(oid, sig_alg)
        return f"{oid} ({human})"
    return sig_alg


def _fingerprint_key(data: str) -> str:
    """Generate a SHA-256 fingerprint for a key/cert identifier."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class CBOMUnificationEngine(ScanStage):
    """Track C — CBOM Unification (Stages 14+15 combined).

    Merges Track A (network/TLS) and Track B (SAST/SCA/Host) data into
    a single, CERT-IN / PNB Annexure-A compliant CBOM JSON schema.
    """

    name = "cbom_unification"
    order = 30
    timeout_seconds = 30
    max_retries = 0
    criticality = StageCriticality.IMPORTANT
    required_fields: list[str] = []  # runs with whatever data is available
    writes_fields = ["unified_cbom_report"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        try:
            protocols = self._build_protocols(ctx)
            certificates = self._build_certificates(ctx)
            algorithms = self._build_algorithms(ctx)
            keys = self._build_keys(ctx, certificates)

            cbom = CBOMReport(
                CBOM_Metadata=CBOMMetadata(
                    target=ctx.domain,
                    timestamp=datetime.now(timezone.utc),
                ),
                Algorithms=algorithms,
                Certificates=certificates,
                Keys=keys,
                Protocols=protocols,
            )

            cbom_dict = cbom.model_dump(mode="json")

            logger.info(
                "[%s] CBOM Unification complete: %d algorithms, %d certs, "
                "%d keys, %d protocols",
                ctx.scan_id,
                len(algorithms), len(certificates),
                len(keys), len(protocols),
            )

            return StageResult(
                status="completed",
                data={"unified_cbom_report": cbom_dict},
            )
        except Exception as exc:
            logger.exception("CBOM Unification failed")
            return StageResult(status="error", error=str(exc))

    # ── A. Protocols & Cipher Suites ─────────────────────────────────

    def _build_protocols(self, ctx: ScanContext) -> list[CBOMProtocol]:
        """Source: Track A (TLS probes) + Track B (host configs)."""
        protocol_map: dict[str, dict[str, Any]] = {}

        # Track A: TLS profiles
        for profile in (ctx.tls_profiles or []):
            if not isinstance(profile, dict):
                continue
            versions = profile.get("tls_versions_supported") or {}
            ciphers = profile.get("accepted_ciphers") or []
            cipher_names = [
                c.get("name", "") if isinstance(c, dict) else str(c)
                for c in ciphers
            ]

            for ver_key, supported in versions.items():
                if not supported:
                    continue
                # Normalize: "TLSv1_3" → "TLS" with version "1.3"
                proto_name, version = self._normalize_protocol_version(ver_key)
                key = f"{proto_name}|{version}"
                if key not in protocol_map:
                    protocol_map[key] = {
                        "name": proto_name,
                        "version": version,
                        "cipher_suites": set(),
                    }
                protocol_map[key]["cipher_suites"].update(c for c in cipher_names if c)

        # Track B: SSH / daemon configs
        for cfg in (ctx.host_config_findings or []):
            if not isinstance(cfg, dict):
                continue
            daemon = cfg.get("daemon", "")
            setting = cfg.get("setting_name", "").lower()

            if daemon == "sshd":
                key = "SSH|2"
                if key not in protocol_map:
                    protocol_map[key] = {"name": "SSH", "version": "2", "cipher_suites": set()}
                if setting in ("ciphers", "kexalgorithms", "macs"):
                    protocol_map[key]["cipher_suites"].update(cfg.get("algorithms_extracted", []))

            elif daemon == "nginx" and setting == "ssl_protocols":
                for proto_str in cfg.get("algorithms_extracted", []):
                    proto_name, version = self._normalize_protocol_version(proto_str)
                    pkey = f"{proto_name}|{version}"
                    if pkey not in protocol_map:
                        protocol_map[pkey] = {"name": proto_name, "version": version, "cipher_suites": set()}

        return [
            CBOMProtocol(
                Name=v["name"],
                Version=v["version"],
                Cipher_Suites=sorted(v["cipher_suites"]),
            )
            for v in protocol_map.values()
        ]

    @staticmethod
    def _normalize_protocol_version(raw: str) -> tuple[str, str]:
        """Normalize strings like 'TLSv1_3', 'TLSv1.2', 'SSLv3' to (name, version)."""
        raw = raw.strip()
        # TLSv1_3, TLS_1_3, TLSv1.3
        m = re.match(r"(?:TLS|tls)[v_\s]*(\d+[._]\d+)", raw)
        if m:
            ver = m.group(1).replace("_", ".")
            return "TLS", ver
        # SSLv3
        m = re.match(r"(?:SSL|ssl)[v_\s]*(\d+)", raw)
        if m:
            return "SSL", m.group(1)
        # SSHv2
        m = re.match(r"(?:SSH|ssh)[v_\s]*(\d+)", raw)
        if m:
            return "SSH", m.group(1)
        return raw, "unknown"

    # ── B. Certificates ──────────────────────────────────────────────

    def _build_certificates(self, ctx: ScanContext) -> list[CBOMCertificate]:
        """Source: Track A (public certs) + Track B (internal .pem/.crt)."""
        certs: list[CBOMCertificate] = []
        seen: set[str] = set()

        # Track A: TLS leaf certs
        for profile in (ctx.tls_profiles or []):
            if not isinstance(profile, dict):
                continue
            leaf = profile.get("leaf_cert")
            if not leaf or not isinstance(leaf, dict):
                continue

            fp = leaf.get("fingerprint_sha256", "")
            if fp in seen:
                continue
            seen.add(fp)

            subject = leaf.get("subject", "unknown")
            issuer = leaf.get("issuer", "unknown")
            key_type = leaf.get("key_type", "unknown")
            key_size = leaf.get("key_size", 0)
            sig_alg = leaf.get("sig_algorithm") or leaf.get("sig_algorithm_oid") or ""

            certs.append(CBOMCertificate(
                Name=self._extract_cn_from_rfc4514(subject),
                Subject_Name=subject,
                Issuer_Name=issuer,
                Not_Valid_Before=leaf.get("valid_from", ""),
                Not_Valid_After=leaf.get("valid_to", ""),
                Signature_Algorithm_Reference=_resolve_sig_oid(sig_alg),
                Subject_Public_Key_Reference=f"{key_type} {key_size}-bit",
                Source="Track A (TLS Probe)",
            ))

        # Track B: Internal certificate files
        for cert_data in (ctx.internal_certificates or []):
            if not isinstance(cert_data, dict):
                continue
            fp = cert_data.get("fingerprint_sha256", "")
            if fp and fp in seen:
                continue
            if fp:
                seen.add(fp)

            subject_cn = cert_data.get("subject_cn") or "unknown"
            issuer_cn = cert_data.get("issuer_cn") or "unknown"
            key_type = cert_data.get("key_type") or "unknown"
            key_size = cert_data.get("key_size") or 0
            sig_alg = cert_data.get("sig_algorithm") or cert_data.get("sig_algorithm_oid") or ""

            # Skip placeholder entries
            if subject_cn.startswith("["):
                continue

            certs.append(CBOMCertificate(
                Name=subject_cn,
                Subject_Name=f"CN={subject_cn}",
                Issuer_Name=f"CN={issuer_cn}",
                Not_Valid_Before=cert_data.get("not_valid_before", ""),
                Not_Valid_After=cert_data.get("not_valid_after", ""),
                Signature_Algorithm_Reference=_resolve_sig_oid(sig_alg),
                Subject_Public_Key_Reference=f"{key_type} {key_size}-bit",
                Source=f"Track B (Internal: {cert_data.get('file_path', 'filesystem')})",
            ))

        return certs

    @staticmethod
    def _extract_cn_from_rfc4514(rfc4514: str) -> str:
        """Extract CN= value from an RFC 4514 string."""
        m = re.search(r"CN=([^,]+)", rfc4514, re.IGNORECASE)
        return m.group(1).strip() if m else rfc4514[:64]

    # ── C. Algorithms ────────────────────────────────────────────────

    def _build_algorithms(self, ctx: ScanContext) -> list[CBOMAlgorithm]:
        """Aggregated from all tracks. Deduplicates by name."""
        algo_map: dict[str, CBOMAlgorithm] = {}

        # Track A: cipher suites from TLS profiles
        for profile in (ctx.tls_profiles or []):
            if not isinstance(profile, dict):
                continue
            for cipher in (profile.get("accepted_ciphers") or []):
                if not isinstance(cipher, dict):
                    continue

                name = cipher.get("name", "")
                if not name or name in algo_map:
                    continue

                bits = cipher.get("bits") or _extract_bits(name) or 128
                primitive = cipher.get("primitive") or _classify_primitive(name)
                mode = cipher.get("mode") or _extract_mode(name)
                csl = cipher.get("classical_security_level")
                if csl is None:
                    csl = _classical_security_level(primitive, bits)

                algo_map[name] = CBOMAlgorithm(
                    Name=name,
                    Primitive=primitive,
                    Mode=mode,
                    Classical_Security_Level=csl,
                    Source="Track A (TLS Probe)",
                )

        # Track A: crypto findings (non-cipher algorithms)
        for finding in (ctx.crypto_findings or []):
            if not isinstance(finding, dict):
                continue
            algo = finding.get("algorithm", "")
            comp = finding.get("component", "")
            if not algo or algo in algo_map:
                continue
            # Skip meta-findings
            if comp in ("crypto_score", "certificate_validity", "certificate_trust"):
                continue

            bits = _extract_bits(algo) or 128
            primitive = _classify_primitive(algo)
            mode = _extract_mode(algo)
            csl = _classical_security_level(primitive, bits)

            algo_map[algo] = CBOMAlgorithm(
                Name=algo,
                Primitive=primitive,
                Mode=mode,
                Classical_Security_Level=csl,
                Source=f"Track A ({comp})",
            )

        # Track B: SAST findings (code-level algorithms)
        for sast in (ctx.sast_findings or []):
            if not isinstance(sast, dict):
                continue
            algo = sast.get("algorithm") or ""
            if not algo:
                continue

            # Normalize name
            normalized = algo.upper().replace("_", "-")
            if normalized in algo_map:
                # Append Track B as a secondary source
                existing = algo_map[normalized]
                if "Track B" not in existing.Source:
                    algo_map[normalized] = existing.model_copy(
                        update={"Source": existing.Source + " + Track B (SAST)"},
                    )
                continue

            bits = _extract_bits(algo) or 256
            primitive = _classify_primitive(algo)
            mode = _extract_mode(algo)
            csl = _classical_security_level(primitive, bits)

            file_path = sast.get("file_path", "")
            file_short = file_path.split("/")[-1] if "/" in file_path else file_path.split("\\")[-1] if "\\" in file_path else file_path

            algo_map[normalized] = CBOMAlgorithm(
                Name=normalized,
                Primitive=primitive,
                Mode=mode,
                Classical_Security_Level=csl,
                Source=f"Track B (SAST: {file_short})",
            )

        # Track B: Host config algorithms (SSH ciphers, nginx ciphers)
        for cfg in (ctx.host_config_findings or []):
            if not isinstance(cfg, dict):
                continue
            for algo_name in (cfg.get("algorithms_extracted") or []):
                if not algo_name or algo_name in algo_map:
                    continue
                bits = _extract_bits(algo_name) or 128
                primitive = _classify_primitive(algo_name)
                mode = _extract_mode(algo_name)
                csl = _classical_security_level(primitive, bits)

                daemon = cfg.get("daemon", "host")
                algo_map[algo_name] = CBOMAlgorithm(
                    Name=algo_name,
                    Primitive=primitive,
                    Mode=mode,
                    Classical_Security_Level=csl,
                    Source=f"Track B (Host Config: {daemon})",
                )

        return list(algo_map.values())

    # ── D. Keys ──────────────────────────────────────────────────────

    def _build_keys(self, ctx: ScanContext, certs: list[CBOMCertificate]) -> list[CBOMKey]:
        """Build keys table. ID = SHA-256 fingerprint of the public key/cert."""
        keys: list[CBOMKey] = []
        seen_ids: set[str] = set()

        # From certificates (Track A + B already merged)
        for cert in certs:
            key_id = _fingerprint_key(f"{cert.Subject_Name}|{cert.Subject_Public_Key_Reference}")
            if key_id in seen_ids:
                continue
            seen_ids.add(key_id)

            # Extract bit size from reference like "RSA 2048-bit"
            bits = _extract_bits(cert.Subject_Public_Key_Reference) or 0

            keys.append(CBOMKey(
                Name=cert.Name,
                id=key_id,
                state="Active",
                size=bits,
                Source=cert.Source,
            ))

        # From SAST (hardcoded secrets / JWT keys)
        for sast in (ctx.sast_findings or []):
            if not isinstance(sast, dict):
                continue
            if sast.get("finding_type") != "hardcoded_secret":
                continue

            secret_type = sast.get("secret_type", "unknown")
            file_path = sast.get("file_path", "unknown")
            key_id = _fingerprint_key(f"{secret_type}|{file_path}|{sast.get('line_number', 0)}")
            if key_id in seen_ids:
                continue
            seen_ids.add(key_id)

            keys.append(CBOMKey(
                Name=f"{secret_type} ({file_path.split('/')[-1] if '/' in file_path else file_path.split(chr(92))[-1] if chr(92) in file_path else file_path})",
                id=key_id,
                state="Active",
                size=256,  # Assumed for JWT/API keys
                Source=f"Track B (SAST: {secret_type})",
            ))

        return keys
