import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from app.scanner.engines.tls_engine import TLSCryptoEngine
from app.scanner.pipeline import ScanContext
from app.scanner.models import TLSProfile, TLSAlpn, TLSValidation

@pytest.fixture
def tls_engine():
    return TLSCryptoEngine()

@pytest.fixture
def ctx():
    return ScanContext(domain="example.com")

@pytest.mark.asyncio
async def test_tls_engine_execute_fallback(tls_engine, ctx):
    ctx.services = []
    ctx.subdomains = ["sub.example.com"]
    
    with patch.object(tls_engine, '_probe_all_versions', new_callable=AsyncMock) as mock_probe, \
         patch.object(tls_engine, '_enumerate_ciphers', new_callable=AsyncMock) as mock_enum, \
         patch.object(tls_engine, '_extract_tls_data', new_callable=AsyncMock) as mock_extract:
         
        mock_probe.return_value = {"TLSv1_3": True}
        mock_enum.return_value = []
        mock_extract.return_value = ([], "TLS_AES_128_GCM_SHA256", None, TLSValidation())
        
        result = await tls_engine.execute(ctx)
        
        assert result.status == "completed"
        # One for example.com (root) and one for sub.example.com
        assert len(result.data["tls_profiles"]) == 2 
        
@pytest.mark.asyncio
async def test_extract_tls_data_mock(tls_engine, ctx):
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        writer = MagicMock()
        writer.wait_closed = AsyncMock()
        mock_connect.return_value = (MagicMock(), writer)
        
        ssl_obj = MagicMock()
        writer.get_extra_info.return_value = ssl_obj
        
        ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        ssl_obj.selected_alpn_protocol.return_value = "h2"
        
        ssl_obj.get_unverified_chain.return_value = [b"mockder"]
        ssl_obj.getpeercert.return_value = b"mockder"
        
        with patch.object(tls_engine, '_parse_cert') as mock_parse:
            mock_cert = MagicMock()
            mock_cert.subject = "CN=example.com"
            mock_cert.sans = ["example.com"]
            mock_parse.return_value = mock_cert
            
            with patch("ssl.create_default_context") as mock_ssl_ctx:
                mock_ctx_instance = MagicMock()
                mock_ssl_ctx.return_value = mock_ctx_instance
                
                cert_chain, negotiated, alpn, validation = await tls_engine._extract_tls_data("example.com", 443, ctx)
                
                assert negotiated == "TLS_AES_256_GCM_SHA384"
                assert alpn is not None
                assert alpn.negotiated == "h2"
                assert validation.hostname_valid is True
                assert validation.chain_valid is True
                assert len(cert_chain) == 1
