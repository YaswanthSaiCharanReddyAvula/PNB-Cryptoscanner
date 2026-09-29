# Crypto Analysis Engine Implementation Plan

## 1. Current Architecture
- `TLSCryptoEngine` writes to `TLSProfile`
- `CryptoAnalysisEngine` reads `TLSProfile` and outputs `CryptoFinding`
- Legacy `crypto_analyzer.py` reads `TLSInfo` and outputs `CryptoComponent` (CBOM)

## 2. Identified Defects
- **C-01**: `cert_chain` is ignored, only `leaf_cert` is analyzed.
- **C-02**: `key_type="EC"` fails to classify.
- **C-03**: Substring PQC signal suppresses HNDL.
- **C-04**: Missing algorithms (`SHA-512`, `DSA`, etc.).
- **C-05**: Loose `startswith` matching in `_match_risk`.
- **Regression**: Explicit forward secrecy tracking is missing.

## 3. Fix Sequence
1. Rewrite `_match_risk` to use canonical identifiers. Add missing algorithms.
2. Update `_classify_cert` to handle `EC` key type explicitly.
3. Update `execute()` to iterate through `profile.cert_chain`.
4. Update `_assess_hndl` to differentiate between advertised PQC and negotiated PQC.
5. Add `_classify_forward_secrecy()` using `cipher.pfs` flag.
6. Replace `crypto_analyzer.py` calls in `common.py` with `CryptoAnalysisEngine` equivalent or map `CryptoFinding` to `CryptoComponent` for legacy API compat.
7. Implement unit and integration tests.

## 4. Compatibility Strategy
We will map `CryptoFinding` outputs back to `CBOM` fields in the router to preserve existing frontend behavior until the frontend transitions entirely to `crypto_findings`.

## 5. Testing Strategy
A comprehensive pytest suite in `tests/test_crypto_analysis_engine.py` covering:
- Unit tests for all mappings (AES, ChaCha, RSA, EC, SHA-512)
- Cert chain tests (weak intermediate)
- HNDL vs advertised PQC
- Dedup logic
