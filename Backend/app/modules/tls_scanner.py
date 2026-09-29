"""
QuantumShield — Enhanced TLS Scanner (Legacy Migration Wrapper)

This module preserves the legacy `scan_tls()` API contract for downstream
consumers (routers, dashboards) but replaces all `sslscan`, `testssl.sh`,
and `zgrab2` subprocess calls with the modern pure-Python `TLSCryptoEngine`.
"""

import asyncio
from typing import List, Dict, Any, Optional

from app.db.models import CertChainEntry, CertificateInfo, TLSInfo, ConfidenceLevel
from app.config import settings
from app.modules.tls_pqc_signals import enrich_tls_info
from app.utils.logger import get_logger

logger = get_logger(__name__)

def _derive_key_exchange(cipher_name: str | None) -> str | None:
    if not cipher_name:
        return "Unknown"
    name = cipher_name.upper().replace("-", "_")
    for token in ["ECDHE", "DHE", "ECDH", "DH", "RSA", "PSK"]:
        if token in name:
            return token
    # TLS 1.3 ciphers do not specify key exchange in the name (e.g. TLS_AES_128_GCM_SHA256)
    if name.startswith("TLS_AES") or name.startswith("TLS_CHACHA20"):
        return "TLSv1.3 Default"
    return "Unknown"

async def scan_tls(
    host: str,
    port: int,
    execution_time_limit_seconds: int | None = None,
) -> TLSInfo:
    """
    Execute TLS inspection using the modern TLSCryptoEngine,
    returning a backward-compatible TLSInfo model.
    """
    from app.scanner.engines.tls_engine import TLSCryptoEngine
    from app.scanner.pipeline import ScanContext
    
    ctx = ScanContext(domain=host)
    engine = TLSCryptoEngine()
    
    logger.info("Internal pure-Python TLS scan on %s:%d...", host, port)
    
    try:
        versions = await engine._probe_all_versions(host, port, ctx)
        ciphers = await engine._enumerate_ciphers(host, port, ctx)
        cert_chain, negotiated, alpn, validation = await engine._extract_tls_data(host, port, ctx)
        
        if not any(versions.values()) and not cert_chain:
            return TLSInfo(host=host, port=port, error="All scanner tools failed or host does not speak TLS.")
        
        # Map back to old TLSInfo structure
        protocols = []
        for k, v in versions.items():
            if v:
                proto_str = k.replace("_", ".")
                protocols.append(proto_str)
                
        tls_version = protocols[-1] if protocols else None
        
        cipher_suite = negotiated or (ciphers[0].name if ciphers else None)
        cipher_bits = None
        if cipher_suite:
            for c in ciphers:
                if c.name == cipher_suite:
                    cipher_bits = c.bits
                    break
        
        fs = any(c.pfs for c in ciphers)
        
        cert_info = None
        if cert_chain:
            leaf = cert_chain[0]
            cert_info = CertificateInfo(
                subject=leaf.subject,
                issuer=leaf.issuer,
                is_self_signed=leaf.is_self_signed,
                not_after=leaf.valid_to,
                signature_algorithm=leaf.sig_algorithm,
                public_key_size=leaf.key_size,
                days_until_expiry=leaf.days_until_expiry
            )
        
        chain_entries = []
        if cert_chain:
            for i, c in enumerate(cert_chain):
                chain_entries.append(CertChainEntry(
                    depth=i,
                    subject=c.subject,
                    issuer=c.issuer,
                    signature_algorithm=c.sig_algorithm,
                    public_key_size=c.key_size,
                    is_valid=validation.chain_valid if validation and validation.chain_valid is not None else True
                ))
                
        confidence = ConfidenceLevel.HIGH if protocols and ciphers else ConfidenceLevel.MEDIUM
        
        all_ciphers = [{"name": c.name, "bits": c.bits or 0, "protocol": tls_version or ""} for c in ciphers]
        
        result = TLSInfo(
            host=host,
            port=port,
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            cipher_bits=cipher_bits,
            key_exchange=_derive_key_exchange(cipher_suite),
            certificate=cert_info,
            all_supported_protocols=protocols,
            all_supported_ciphers=all_ciphers,
            supports_forward_secrecy=fs,
            cert_chain=chain_entries,
            confidence=confidence
        )
        return enrich_tls_info(result)
    except Exception as exc:
        logger.error("Unhandled internal TLS scan exception on %s:%d : %s", host, port, exc, exc_info=True)
        return TLSInfo(host=host, port=port, error=f"Unhandled internal TLS scan exception: {str(exc)}")
