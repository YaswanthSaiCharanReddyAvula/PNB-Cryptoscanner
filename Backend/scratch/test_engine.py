import asyncio
from app.scanner.models import TLSProfile, CipherDetail, CertificateDetail
from app.scanner.engines.crypto_analysis import CryptoAnalysisEngine
from app.scanner.pipeline import ScanContext

async def test():
    ctx = ScanContext(domain="example.com")
    
    # Test A: Modern TLS
    p1 = TLSProfile(
        host="test-a.com",
        port=443,
        tls_versions_supported={"TLSv1_3": True},
        accepted_ciphers=[CipherDetail(name="TLS_AES_256_GCM_SHA384", encryption="AES-256", kex="any (TLS 1.3)", mac="AEAD", pfs=True)],
        negotiated_cipher="TLS_AES_256_GCM_SHA384",
        leaf_cert=CertificateDetail(
            subject="CN=test-a.com",
            issuer="CN=CA",
            serial="1",
            valid_from="2020-01-01T00:00:00Z",
            valid_to="2030-01-01T00:00:00Z",
            key_type="RSA",
            key_size=2048,
            sig_algorithm="sha256WithRSAEncryption"
        )
    )
    
    # Test B: Weak Algorithm
    p2 = TLSProfile(
        host="test-b.com",
        port=443,
        tls_versions_supported={"TLSv1_2": True},
        accepted_ciphers=[CipherDetail(name="TLS_RSA_WITH_3DES_EDE_CBC_SHA", encryption="3DES", kex="RSA", mac="SHA1", pfs=False)],
        negotiated_cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    )
    
    # Test C: Unknown Algorithm (EC)
    p3 = TLSProfile(
        host="test-c.com",
        port=443,
        tls_versions_supported={"TLSv1_3": True},
        accepted_ciphers=[],
        leaf_cert=CertificateDetail(
            subject="CN=test-c.com",
            issuer="CN=CA",
            serial="1",
            valid_from="2020-01-01T00:00:00Z",
            valid_to="2030-01-01T00:00:00Z",
            key_type="EC",
            key_size=256,
            sig_algorithm="ecdsa-with-SHA256"
        )
    )
    
    # Test D: PQC
    p4 = TLSProfile(
        host="test-d.com",
        port=443,
        tls_versions_supported={"TLSv1_3": True},
        accepted_ciphers=[],
        pqc_signals=["kex:kyber"]
    )
    
    ctx.tls_profiles = [p1.model_dump(), p2.model_dump(), p3.model_dump(), p4.model_dump()]
    
    engine = CryptoAnalysisEngine()
    result = await engine.execute(ctx)
    
    import json
    for f in result.data["crypto_findings"]:
        print(json.dumps(f))

if __name__ == "__main__":
    asyncio.run(test())
