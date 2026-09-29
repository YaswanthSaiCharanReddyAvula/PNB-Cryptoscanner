import asyncio
from app.scanner.models import TLSProfile, CipherDetail
from app.scanner.engines.crypto_analysis import CryptoAnalysisEngine
from app.scanner.pipeline import ScanContext

async def test():
    ctx = ScanContext()
    
    p1 = TLSProfile(
        host="advertised-only.com",
        port=443,
        accepted_ciphers=[CipherDetail(name="TLS_RSA_WITH_AES_128_GCM_SHA256", kex="RSA")],
        negotiated_cipher="TLS_RSA_WITH_AES_128_GCM_SHA256",
        pqc_signals=["kex:kyber"]  # Simulated advertisement via some supported cipher
    )
    
    p2 = TLSProfile(
        host="negotiated-hybrid.com",
        port=443,
        accepted_ciphers=[CipherDetail(name="TLS_AES_256_GCM_SHA384", kex="any (TLS 1.3)")],
        negotiated_cipher="TLS_AES_256_GCM_SHA384",
        pqc_signals=["negotiated:kyber"]
    )
    
    ctx.tls_profiles = [p1.model_dump(), p2.model_dump()]
    engine = CryptoAnalysisEngine()
    res = await engine.execute(ctx)
    for f in res.data["crypto_findings"]:
        if f.get("component") == "hndl_risk":
            print(f["host"], f["hndl_risk"])

asyncio.run(test())
