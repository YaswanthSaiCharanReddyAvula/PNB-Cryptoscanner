"""
QuantumShield — Crypto Normalization Layer
"""

import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple


class CryptoNormalization:
    """Centralized normalization of cryptographic algorithms, primitives, and modes."""
    
    _cipher_cache: Optional[dict[str, dict]] = None

    @classmethod
    def _load_cipher_registry(cls) -> dict[str, dict]:
        if cls._cipher_cache is None:
            path = Path(__file__).resolve().parent.parent / "data" / "cipher_registry.json"
            try:
                cls._cipher_cache = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                cls._cipher_cache = {}
        return cls._cipher_cache

    @classmethod
    def is_compound_cipher_suite(cls, name: str) -> bool:
        """Determines if a name represents a compound TLS/SSL cipher suite."""
        if not name or not isinstance(name, str):
            return False
        clean = name.strip()
        upper = clean.upper()
        
        # Obvious TLS/SSL prefixes
        if upper.startswith("TLS_") or upper.startswith("SSL_"):
            return True
            
        # Registry match
        registry = cls._load_cipher_registry()
        if upper in registry or clean in registry:
            return True
            
        # Compound separator pattern (e.g. ECDHE-RSA-AES128-GCM-SHA256, DHE-RSA-AES256-SHA)
        parts = re.split(r"[-_]", upper)
        if len(parts) >= 3:
            has_kex_auth = any(p in ("ECDHE", "ECDH", "DHE", "DH", "RSA", "ECDSA", "DSA") for p in parts)
            has_cipher = any(p.startswith("AES") or p in ("CHACHA20", "3DES", "DES", "RC4") for p in parts)
            if has_kex_auth and has_cipher:
                return True

        return False

    @classmethod
    def decompose_cipher_suite(cls, name: str) -> List[Dict[str, Any]]:
        """
        Decomposes a compound cipher suite into its constituent cryptographic primitives.
        Returns a list of dicts with keys:
          - 'primitive': canonical algorithm name in taxonomy
          - 'role': 'key_exchange' | 'authentication' | 'encryption' | 'hash'
          - 'is_kex': bool
          - 'key_size': Optional[int]
          - 'original_suite': str
        """
        if not name or not isinstance(name, str):
            return []

        clean = name.strip()
        upper = clean.upper()
        registry = cls._load_cipher_registry()
        entry = registry.get(upper) or registry.get(clean)
        components: List[Dict[str, Any]] = []

        if entry:
            # 1. Key Exchange
            kex = entry.get("kex")
            if kex and "any" not in kex.lower() and kex.upper() != "NONE":
                components.append({
                    "primitive": kex.upper(),
                    "role": "key_exchange",
                    "is_kex": True,
                    "key_size": None,
                    "original_suite": clean,
                })

            # 2. Authentication / Signature
            auth = entry.get("auth")
            if auth and "any" not in auth.lower() and auth.upper() != "NONE":
                components.append({
                    "primitive": auth.upper(),
                    "role": "authentication",
                    "is_kex": False,
                    "key_size": None,
                    "original_suite": clean,
                })

            # 3. Encryption
            enc = entry.get("encryption")
            if enc:
                bits = entry.get("bits") or cls.extract_bits(enc) or cls.extract_bits(clean)
                enc_upper = enc.upper()
                if "AES" in enc_upper:
                    enc_prim = "AES-256" if bits == 256 else "AES-128"
                    bits = bits or (256 if enc_prim == "AES-256" else 128)
                elif "CHACHA20" in enc_upper:
                    enc_prim = "CHACHA20"
                    bits = bits or 256
                elif "3DES" in enc_upper or "DES-EDE" in enc_upper:
                    enc_prim = "3DES"
                    bits = bits or 168
                else:
                    enc_prim = enc_upper

                components.append({
                    "primitive": enc_prim,
                    "role": "encryption",
                    "is_kex": False,
                    "key_size": bits,
                    "original_suite": clean,
                })

            # 4. Hash / MAC
            mac = entry.get("mac")
            hash_prim = None
            if mac and mac.upper() != "AEAD":
                if "SHA384" in mac.upper() or "SHA-384" in mac.upper():
                    hash_prim = "SHA-384"
                elif "SHA256" in mac.upper() or "SHA-256" in mac.upper():
                    hash_prim = "SHA-256"
                elif "SHA512" in mac.upper() or "SHA-512" in mac.upper():
                    hash_prim = "SHA-512"
                elif "SHA1" in mac.upper() or "SHA-1" in mac.upper() or mac.upper() == "SHA":
                    hash_prim = "SHA-1"
                elif "MD5" in mac.upper():
                    hash_prim = "MD5"

            # Check suite name suffix if AEAD or not identified from mac field
            if not hash_prim:
                if upper.endswith("SHA384") or upper.endswith("SHA-384"):
                    hash_prim = "SHA-384"
                elif upper.endswith("SHA256") or upper.endswith("SHA-256"):
                    hash_prim = "SHA-256"
                elif upper.endswith("SHA512") or upper.endswith("SHA-512"):
                    hash_prim = "SHA-512"
                elif upper.endswith("SHA") or upper.endswith("SHA1") or upper.endswith("SHA-1"):
                    hash_prim = "SHA-1"
                elif upper.endswith("MD5"):
                    hash_prim = "MD5"

            if hash_prim:
                components.append({
                    "primitive": hash_prim,
                    "role": "hash",
                    "is_kex": False,
                    "key_size": cls.extract_bits(hash_prim),
                    "original_suite": clean,
                })

            return components

        # Fallback: Parse compound suite string via standard tokens
        norm_tokens = upper.replace("TLS_", "").replace("SSL_", "").replace("_WITH_", "-").replace("_", "-")
        tokens = norm_tokens.split("-")

        # Key Exchange
        kex = None
        for tok in ("ECDHE", "ECDH", "DHE", "DH", "X25519"):
            if tok in tokens:
                kex = tok
                break
        if kex:
            components.append({
                "primitive": kex,
                "role": "key_exchange",
                "is_kex": True,
                "key_size": None,
                "original_suite": clean,
            })

        # Auth
        auth = None
        for tok in ("RSA", "ECDSA", "DSA", "ED25519"):
            if tok in tokens:
                auth = tok
                break
        if auth:
            components.append({
                "primitive": auth,
                "role": "authentication",
                "is_kex": False,
                "key_size": None,
                "original_suite": clean,
            })

        # Encryption
        enc_prim = None
        bits = cls.extract_bits(clean)
        for tok in tokens:
            if "AES" in tok:
                enc_prim = "AES-256" if (bits == 256 or "256" in tok) else "AES-128"
                bits = 256 if enc_prim == "AES-256" else 128
                break
            elif "CHACHA20" in tok:
                enc_prim = "CHACHA20"
                bits = 256
                break
            elif "3DES" in tok or "DES" in tok:
                enc_prim = "3DES"
                bits = 168
                break
        if enc_prim:
            components.append({
                "primitive": enc_prim,
                "role": "encryption",
                "is_kex": False,
                "key_size": bits,
                "original_suite": clean,
            })

        # Hash
        hash_prim = None
        for tok in tokens:
            if "SHA384" in tok or "SHA-384" in tok:
                hash_prim = "SHA-384"
                break
            elif "SHA256" in tok or "SHA-256" in tok:
                hash_prim = "SHA-256"
                break
            elif "SHA512" in tok or "SHA-512" in tok:
                hash_prim = "SHA-512"
                break
            elif tok in ("SHA1", "SHA-1", "SHA"):
                hash_prim = "SHA-1"
                break
            elif "MD5" in tok:
                hash_prim = "MD5"
                break
        if hash_prim:
            components.append({
                "primitive": hash_prim,
                "role": "hash",
                "is_kex": False,
                "key_size": cls.extract_bits(hash_prim),
                "original_suite": clean,
            })

        return components

    @classmethod
    def resolve_primitive(
        cls, name: str, default_kex: bool = False
    ) -> Tuple[Optional[str], Optional[int], bool, Optional[str]]:
        """
        Normalizes any single algorithm name or curve alias into canonical taxonomy form.
        Returns: (canonical_name, key_size, is_kex, curve)
        """
        if not name or not isinstance(name, str):
            return None, None, default_kex, None

        clean = name.strip()
        upper = clean.upper().replace(" ", "-").replace("_", "-")

        # 1. RSA variations (RSA-2048, RSA_4096, RSA1024, RSA-PSS)
        if "RSA-PSS" in upper:
            bits = cls.extract_bits(upper)
            return "RSA-PSS", bits, False, None
        if upper.startswith("RSA") or upper == "RSA":
            bits = cls.extract_bits(upper)
            return "RSA", bits, default_kex, None

        # 2. AES variations (AES-256, AES256, AES_128_GCM, AES-128-CBC)
        if "AES" in upper:
            bits = cls.extract_bits(upper) or 128
            canonical = "AES-256" if bits == 256 else "AES-128"
            return canonical, bits, False, None

        # 3. ChaCha20 / 3DES
        if "CHACHA20" in upper:
            return "CHACHA20", 256, False, None
        if "3DES" in upper or "TRIPLEDES" in upper or "DES-EDE" in upper:
            return "3DES", 168, False, None

        # 4. Elliptic Curves & Aliases
        # NIST curves: secp256r1 / prime256v1 / P-256 / nistp256
        if any(c in upper for c in ("SECP256R1", "PRIME256V1", "NISTP256", "P-256", "P256")):
            canonical = "ECDH" if default_kex else "ECDSA"
            return canonical, 256, default_kex, "secp256r1"
        if any(c in upper for c in ("SECP384R1", "NISTP384", "P-384", "P384")):
            canonical = "ECDH" if default_kex else "ECDSA"
            return canonical, 384, default_kex, "secp384r1"
        if any(c in upper for c in ("SECP521R1", "NISTP521", "P-521", "P521")):
            canonical = "ECDH" if default_kex else "ECDSA"
            return canonical, 521, default_kex, "secp521r1"
        if "SECP256K1" in upper:
            canonical = "ECDH" if default_kex else "ECDSA"
            return canonical, 256, default_kex, "secp256k1"
        if any(c in upper for c in ("X25519", "CURVE25519", "CV25519")):
            return "X25519", 256, True, "curve25519"
        if any(c in upper for c in ("ED25519", "EDDSA")):
            return "ED25519", 256, False, "ed25519"
        if upper in ("ECDSA", "ECDH", "ECDHE", "DHE", "DH", "DSA", "EC", "ECC"):
            bits = cls.extract_bits(upper)
            is_kex = default_kex or upper in ("ECDH", "ECDHE", "DHE", "DH", "X25519")
            return upper, bits, is_kex, None

        # 5. Hashes
        if upper in ("SHA384", "SHA-384"):
            return "SHA-384", 384, False, None
        if upper in ("SHA256", "SHA-256"):
            return "SHA-256", 256, False, None
        if upper in ("SHA512", "SHA-512"):
            return "SHA-512", 512, False, None
        if upper in ("SHA1", "SHA-1", "SHA"):
            return "SHA-1", 160, False, None
        if upper == "MD5":
            return "MD5", 128, False, None

        # 6. Post-Quantum Algorithms & Hybrids
        if "X25519KYBER" in upper:
            return "X25519KYBER", None, True, None
        if "ML-KEM" in upper or "KYBER" in upper:
            bits = cls.extract_bits(upper) or 768
            return "ML-KEM", bits, True, None
        if "ML-DSA" in upper or "DILITHIUM" in upper:
            return "ML-DSA", None, False, None
        if "FALCON" in upper:
            return "FALCON", None, False, None
        if "SPHINCS" in upper:
            return "SPHINCS+", None, False, None

        return None, None, default_kex, None
    
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
        "EDDSA":     "signature",
        "ED25519":   "signature",
        "ECDHE":     "key_agreement",
        "ECDH":      "key_agreement",
        "DHE":       "key_agreement",
        "DH":        "key_agreement",
        "X25519":    "key_agreement",
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

    _MODE_TOKENS = ("GCM", "CBC", "CCM", "CTR", "ECB", "CFB", "OFB", "POLY1305", "XTS")
    
    @classmethod
    def normalize_algorithm(cls, name: str) -> str:
        """
        Normalize algorithm name.
        SHA256 -> SHA-256
        hashlib.sha256 -> SHA-256
        """
        if not name: return name
        name = name.split(".")[-1].upper()
        
        # Insert dash for SHA variants if missing
        if re.match(r"^SHA\d+$", name):
            name = name.replace("SHA", "SHA-")
            
        return name

    @classmethod
    def classify_primitive(cls, name: str) -> str:
        """Map an algorithm name to its primitive type."""
        if not name: return "unknown"
        upper = name.upper().replace("-", "").replace("_", "")
        for token, prim in cls._PRIMITIVE_MAP.items():
            if token.upper().replace("-", "") in upper:
                return prim
        return "unknown"

    @classmethod
    def extract_mode(cls, name: str) -> str:
        """Extract the operational mode from an algorithm/cipher name."""
        if not name: return "N/A"
        upper = name.upper()
        for mode in cls._MODE_TOKENS:
            if mode in upper:
                return mode
        return "N/A"

    @classmethod
    def extract_bits(cls, name: str) -> Optional[int]:
        """Pull bit-size from a name like 'AES-256-GCM' or 'RSA 2048'."""
        if not name: return None
        nums = re.findall(r"\d+", name)
        for n in nums:
            val = int(n)
            if val in (64, 128, 192, 256, 384, 512, 1024, 2048, 3072, 4096, 521, 7680):
                return val
        return None

    @classmethod
    def classical_security_level(cls, primitive: str, bits: int) -> int:
        """Compute classical security level in bits per the architecture spec."""
        if not primitive or not bits: return bits or 128
        
        prim_lower = primitive.lower()
        if "symmetric" in prim_lower or "hash" in prim_lower:
            return bits
        if "rsa" in prim_lower or "signature" in prim_lower:
            rsa_map = {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192}
            return rsa_map.get(bits, 112)
        if "key_agreement" in prim_lower or "ecc" in prim_lower:
            ecc_map = {256: 128, 384: 192, 521: 256}
            return ecc_map.get(bits, bits // 2)
        return bits
