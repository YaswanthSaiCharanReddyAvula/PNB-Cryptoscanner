"""
QuantumShield — Crypto Normalization Layer
"""

import re
from typing import Optional, Tuple


class CryptoNormalization:
    """Centralized normalization of cryptographic algorithms, primitives, and modes."""
    
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
