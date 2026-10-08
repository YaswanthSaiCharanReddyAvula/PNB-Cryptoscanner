"""
Phase 4 — Quantum Algorithm Taxonomy
"""

from typing import Any, Dict

# Preserved and adapted from the existing ALGORITHM_RISK_MAP
QUANTUM_ALGORITHM_TAXONOMY: Dict[str, Dict[str, Any]] = {
    # Key exchange
    "RSA": {
        "family": "asymmetric",
        "quantum_attack": "Shor",
        "affected": True,
        "default_quantum_class": "high",
        "hndl_capable": True,
    },
    "ECDHE": {
        "family": "asymmetric",
        "quantum_attack": "Shor",
        "affected": True,
        "default_quantum_class": "high",
        "hndl_capable": True,
    },
    "ECDH": {
        "family": "asymmetric",
        "quantum_attack": "Shor",
        "affected": True,
        "default_quantum_class": "high",
        "hndl_capable": True,
    },
    "DHE": {
        "family": "asymmetric",
        "quantum_attack": "Shor",
        "affected": True,
        "default_quantum_class": "high",
        "hndl_capable": True,
    },
    "DH": {
        "family": "asymmetric",
        "quantum_attack": "Shor",
        "affected": True,
        "default_quantum_class": "high",
        "hndl_capable": True,
    },
    
    # Signatures
    "ECDSA": {
        "family": "asymmetric",
        "quantum_attack": "Shor",
        "affected": True,
        "default_quantum_class": "high",
        "hndl_capable": False,
    },
    "DSA": {
        "family": "asymmetric",
        "quantum_attack": "Shor",
        "affected": True,
        "default_quantum_class": "high",
        "hndl_capable": False,
    },
    "ED25519": {
        "family": "asymmetric",
        "quantum_attack": "Shor",
        "affected": True,
        "default_quantum_class": "high",
        "hndl_capable": False,
    },
    "RSA-PSS": {
        "family": "asymmetric",
        "quantum_attack": "Shor",
        "affected": True,
        "default_quantum_class": "high",
        "hndl_capable": False,
    },

    # Symmetric encryption
    "AES-128": {
        "family": "symmetric",
        "quantum_attack": "Grover",
        "affected": True,
        "default_quantum_class": "medium",
        "hndl_capable": False,
    },
    "AES-256": {
        "family": "symmetric",
        "quantum_attack": "Grover",
        "affected": True,
        "default_quantum_class": "low",
        "hndl_capable": False,
    },
    "CHACHA20": {
        "family": "symmetric",
        "quantum_attack": "Grover",
        "affected": True,
        "default_quantum_class": "low",
        "hndl_capable": False,
    },
    "3DES": {
        "family": "symmetric",
        "quantum_attack": "Grover",
        "affected": True,
        "default_quantum_class": "critical",
        "hndl_capable": False,
    },

    # Hash / MAC
    "MD5": {
        "family": "hash",
        "quantum_attack": "Grover",
        "affected": True,
        "default_quantum_class": "critical",
        "hndl_capable": False,
    },
    "SHA-1": {
        "family": "hash",
        "quantum_attack": "Grover",
        "affected": True,
        "default_quantum_class": "high",
        "hndl_capable": False,
    },
    "SHA-256": {
        "family": "hash",
        "quantum_attack": "Grover",
        "affected": True,
        "default_quantum_class": "medium",
        "hndl_capable": False,
    },
    "SHA-384": {
        "family": "hash",
        "quantum_attack": "Grover",
        "affected": True,
        "default_quantum_class": "low",
        "hndl_capable": False,
    },
    "SHA-512": {
        "family": "hash",
        "quantum_attack": "Grover",
        "affected": True,
        "default_quantum_class": "low",
        "hndl_capable": False,
    },

    # Post-quantum algorithms
    "ML-KEM": {
        "family": "pqc",
        "quantum_attack": "none",
        "affected": False,
        "default_quantum_class": "none",
        "hndl_capable": False,
    },
    "ML-DSA": {
        "family": "pqc",
        "quantum_attack": "none",
        "affected": False,
        "default_quantum_class": "none",
        "hndl_capable": False,
    },
    "X25519KYBER": {
        "family": "hybrid",
        "quantum_attack": "none",
        "affected": False,
        "default_quantum_class": "none",
        "hndl_capable": False,
    }
}
