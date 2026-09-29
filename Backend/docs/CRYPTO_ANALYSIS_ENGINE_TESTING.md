# Crypto Analysis Engine Testing Plan

## 1. Unit Tests (`tests/test_crypto_analysis_engine.py`)
- Mappings for all algorithms (AES, RSA, EC, SHA-512, etc.)
- Normalization (e.g. `sha256WithRSAEncryption` to `SHA-256`)
- Strict match verification (`RSA-PSS` vs `RSA`)

## 2. Certificate Tests
- Weak leaf cert
- Weak intermediate cert
- Weak root cert
- EC key tests (ensuring EC doesn't fail mapping)
- RSA < 2048

## 3. HNDL & PQC Tests
- True hybrid KEX disables HNDL
- Advertised PQC but negotiated RSA keeps HNDL
- Unknown PQC state

## 4. Forward Secrecy Tests
- ECDHE negotiated -> FS present
- Static RSA -> FS absent

## 5. Integration
- End to end test inside `ScanContext` to verify `crypto_findings` persist into DB mock.
