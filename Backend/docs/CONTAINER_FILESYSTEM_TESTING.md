# Container & Filesystem Test Suite Documentation
## ECDAT / QuantumShield Test Specifications & Execution

### 1. Test Architecture
The test suite consists of automated tests located in `Backend/tests/`:
- `test_container_filesystem.py`: Tests safe traversal, file classification, depth limits, path traversal rejection, symlink escape rejection, archive bomb protection, and OCI/Docker whiteout resolution.
- `test_crypto_artifacts.py`: Tests deep X.509 certificate parsing, private key extraction with zero secret leakage, password-protected key detection, public key parsing, key-certificate cryptographic correlation, PKCS#12/JKS keystores, configuration files, environment variable redaction, PQC algorithms, and package discovery.
- `test_container_pipeline_integration.py`: Tests end-to-end container image archive inspection with `InspectionCoordinator`, Stage 15 `HostScannerEngine` execution with `ScanContext`, and Track C `CBOMUnificationEngine` generation.

### 2. Execution Commands
To execute the container & filesystem test suite:
```bash
# In Backend/
python -m pytest tests/test_container_filesystem.py tests/test_crypto_artifacts.py tests/test_container_pipeline_integration.py -v
```

To execute the entire regression suite:
```bash
python -m pytest tests/
```

### 3. Verification Criteria
- All 106 automated tests across the entire repository pass without errors.
- Whiteout deletion markers correctly remove deleted files from the final filesystem view.
- Private keys never leak into serialized outputs.
- Tar bombs and traversal attacks (`../`, symlinks to `/etc`) are rejected safely.
- CBOM output reflects certificates, keys, algorithms, and protocols from container and filesystem sources.
