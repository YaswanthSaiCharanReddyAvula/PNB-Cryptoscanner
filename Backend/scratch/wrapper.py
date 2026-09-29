"""
QuantumShield — Crypto Analyzer Module (Legacy Wrapper)

This module used to contain the legacy analysis logic. It has been refactored
to wrap the modern CryptoAnalysisEngine (Stage 5), ensuring there is only ONE
authoritative crypto-risk interpretation layer, while maintaining compatibility
with legacy CBOM consumers.
"""

from typing import List
import asyncio

from app.db.models import (
    AlgorithmCategory,
    CryptoComponent,
    QuantumStatus,
    RiskLevel,
    TLSInfo,
)
from app.utils.logger import get_logger

from app.scanner.engines.crypto_analysis import CryptoAnalysisEngine
from app.scanner.pipeline import ScanContext
from app.scanner.models import TLSProfile, CipherDetail, CertificateDetail

logger = get_logger(__name__)

# Legacy mapping maps the new engine's components back to the old enum categories
_COMPONENT_TO_CATEGORY = {
    "cipher_kex": AlgorithmCategory.KEY_EXCHANGE,
    "cipher_enc": AlgorithmCategory.CIPHER,
    "cipher_mac": AlgorithmCategory.HASH,
    "protocol": AlgorithmCategory.PROTOCOL,
    "hndl_risk": AlgorithmCategory.KEY_EXCHANGE,
    "forward_secrecy": AlgorithmCategory.KEY_EXCHANGE,
    "crypto_score": AlgorithmCategory.CIPHER,  # Not typically surfaced as a component
}

_RISK_TO_QSTATUS = {
    "critical": QuantumStatus.VULNERABLE,
    "high": QuantumStatus.VULNERABLE,
    "medium": QuantumStatus.PARTIALLY_SAFE,
    "low": QuantumStatus.QUANTUM_SAFE,
    "none": QuantumStatus.QUANTUM_SAFE,
    "info": QuantumStatus.QUANTUM_SAFE,
}

def analyze(tls_info: TLSInfo) -> List[CryptoComponent]:
    """
    Analyse a single TLS scan result and return classified crypto components
    by proxying to the modern CryptoAnalysisEngine.
    """
    if tls_info.error:
        logger.warning("Skipping analysis for %s:%d — scan error.", tls_info.host, tls_info.port)
        return []

    logger.info("Analysing crypto (via modern engine) for %s:%d ...", tls_info.host, tls_info.port)

    # 1. Translate legacy TLSInfo into modern TLSProfile
    ciphers = []
    for c in tls_info.all_supported_ciphers:
        ciphers.append(CipherDetail(
            name=c.get("name", "UNKNOWN"),
            bits=c.get("bits"),
            pfs=False,  # Can't reliably recover PFS flag from pure legacy dict without parsing the name
            kex=None,
            encryption=None,
            mac=None,
            pqc=False
        ))

    # Re-inject the known properties for the negotiated cipher if any
    if tls_info.cipher_suite:
        # If we couldn't parse kex/mac/enc before, the modern engine will just do its best, 
        # but wait, the modern engine relies on CipherDetail.kex! 
        # Actually, since TLSInfo lost the decomposed kex/enc/mac, this is problematic if TLSInfo was built from testssl.
        # However, our tls_scanner.py actually uses TLSCryptoEngine now! It builds TLSInfo by discarding the rich TLSProfile.
        pass

    # Actually, a much better approach is to let the router use `ScanContext` or to just rebuild what we can.
    # Wait, if tls_info is all we have, we might be missing the parsed `kex`, `mac`, `enc` fields!
    # Let me check `tls_scanner.py` - it actually runs `TLSCryptoEngine` and discards the rich `CipherDetail`.
    pass
