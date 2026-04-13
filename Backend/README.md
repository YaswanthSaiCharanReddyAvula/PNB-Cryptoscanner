# QuantumShield — Quantum-Proof Cryptographic Scanner

A modular FastAPI backend that scans banking systems for cryptographic vulnerabilities, builds a **Cryptographic Bill of Materials (CBOM)**, evaluates **Quantum Readiness**, and recommends **Post-Quantum Cryptography (PQC)** migration paths.

## Architecture

```
Client (React) ──▶ FastAPI ──▶ 8-Stage Scanning Pipeline ──▶ MongoDB

  ┌──────────────────────────────────────────────────────────────┐
  │                    SCANNING PIPELINE                         │
  │                                                              │
  │  1. Asset Discovery ──▶ 2. TLS Scanner ──▶ 3. Crypto        │
  │     (subfinder/nmap)     (all ciphers,      Analyzer         │
  │                           all protocols,    (classify &      │
  │                           cert chain,        risk-rate)      │
  │                           forward secrecy)                   │
  │                                                              │
  │  4. Quantum Risk  ──▶ 5. CBOM         ──▶ 6. PQC            │
  │     Engine (0-100)      Generator          Recommendations   │
  │                                            (Kyber/Dilithium) │
  │                                                              │
  │  7. HTTP Headers  ──▶ 8. CVE / Attack                       │
  │     Scanner (HSTS,      Mapper (POODLE,                     │
  │     CSP, 11+ checks)    BEAST, DROWN, 17 rules)            │
  └──────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.11+ | Required |
| MongoDB | Running on `localhost:27017` (configurable) |
| nmap | For port scanning (optional, graceful fallback) |
| subfinder | For subdomain enumeration (optional, graceful fallback) |

### Installation

```bash
cd Backend

# Create virtual environment (required on Kali Linux)
python3 -m venv ~/quantumshield-venv
source ~/quantumshield-venv/bin/activate

pip install -r requirements.txt
```

### Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

API docs available at **http://localhost:8000/docs**

### Docker and Google Cloud

Production container (scanner toolchain + uvicorn):

```bash
docker build -t quantumshield-api -f Backend/Dockerfile Backend
docker run --rm -p 8000:8000 --env-file Backend/.env quantumshield-api
```

Cloud SQL, MongoDB Atlas, Artifact Registry, GCE vs Cloud Run, CORS, HTTPS, billing alerts, and Firebase/GCS static hosting are documented in **[deploy/gcp/README.md](../deploy/gcp/README.md)**. Use **[deploy/gcp/env.cloud.example](../deploy/gcp/env.cloud.example)** as an env template for the VM or Secret Manager (never commit real credentials).

### Environment Variables

Create a `.env` file in the `Backend/` directory:

```env
MONGO_URI=mongodb://localhost:27017
MONGO_DB_NAME=quantumshield
# "*" allows any browser origin (default). Or use comma-separated origins.
CORS_ORIGINS=*
LOG_LEVEL=INFO
SCAN_TIMEOUT=120
```

### Backend on Kali VM, frontend on Windows

1. On **Kali**, bind the API to all interfaces: `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload` (MongoDB must be reachable from Kali, usually `localhost`).
2. Note the VM IP from Windows (e.g. `192.168.56.102` for VirtualBox host-only).
3. On **Windows**, set `VITE_API_BASE_URL=http://<VM_IP>:8000/api/v1` in `Frontend/.env.local` (recommended) or `Frontend/.env`, then restart `npm run dev`.
4. In **Kali** `Backend/.env`, use `CORS_ORIGINS=*` for any dev URL, or list the exact browser origins comma-separated if you need credentialed CORS.
5. Allow the port through the VM firewall if needed: `sudo ufw allow 8000/tcp` (or equivalent).

### Shared folder (same repo on Windows + Kali)

| Do | Avoid |
|----|--------|
| Copy `Backend/.env.example` → `Backend/.env` on Kali; use `Backend/.env.local` on Kali for overrides only | Sharing one **Python `venv`** between OSes — create the venv only on Linux (`python3 -m venv .venv && source .venv/bin/activate`) |
| Run `npm install` / `npm run dev` on **Windows** for the frontend | Committing `node_modules` — it is gitignored; reinstall after sync if needed |
| Use `Frontend/.env.local` for the Windows-only API URL | Putting secrets in tracked `.env` files — add `Backend/.env` / `Frontend/.env` to git only if your team policy allows (defaults are gitignored in this repo) |

After cloning or changing branches on Kali: `pip install -r requirements.txt` inside your Linux venv. On Windows: `npm ci` or `npm install` in `Frontend/`.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scan` | Trigger a full 8-stage cryptographic scan |
| `GET` | `/api/v1/results/{domain}` | Get full scan results (TLS, CBOM, CVEs, headers) |
| `GET` | `/api/v1/cbom/{domain}` | Get Cryptographic Bill of Materials |
| `GET` | `/api/v1/quantum-score/{domain}` | Get quantum readiness score + PQC recommendations |
| `GET` | `/health` | Health check |
| `GET` | `/api/v1/reports/export-bundle` | JSON bundle: CBOM report, TLS, quantum score, assets (latest completed scan; optional `?domain=`) |
| `GET` | `/api/v1/migration/roadmap` | Phased migration waves derived from scan signals (optional `?domain=`) |
| `GET` | `/api/v1/threat-model/summary` | Shor / Grover / HNDL context plus counts from latest scan (optional `?domain=`) |

### Demo flow (local)

1. Start MongoDB, then from `Backend/`: `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload`.
2. Confirm `GET http://localhost:8000/health` returns `"status": "healthy"`.
3. From `Frontend/`: `npm run dev` (default port **8080**). Set `VITE_API_BASE_URL=http://localhost:8000/api/v1` if needed.
4. Open the app, sign in, run **Scan** on a domain from the dashboard; then open **CBOM**, **PQC Posture**, and **Cyber Rating**. The top bar shows **API: connected** when the backend is reachable.

## Detailed File Descriptions

This section outlines every file in the backend, detailing its role, the tools and libraries it utilizes, and any specific commands it executes.

### Top-Level Files

#### `app/main.py`
- **What it does:** The FastAPI entry point. It sets up the ASGI application, configures CORS middleware, handles global exceptions, sets up the application lifespan (database connection/disconnection events), and registers core REST mapping routes.
- **Tools/Libraries used:** `FastAPI` (web framework), `uvicorn` (ASGI web server), `contextlib.asynccontextmanager`.
- **Commands used to run:** `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload`

#### `app/config.py`
- **What it does:** Centralized application configuration mapping. It reads configurations from a `.env` file or environment variables, defining application constants like MongoDB URI, default scan timeout, and allowed CORS origins.
- **Tools/Libraries used:** `pydantic-settings` (loading env variables safely with typings).

#### `requirements.txt`
- **What it does:** Lists all the Python dependencies required for the backend to function.
- **Tools/Libraries used:** `fastapi`, `uvicorn`, `motor` (MongoDB async), `pydantic`, `cryptography`, etc.
- **Commands used to install:** `pip install -r requirements.txt`

---

### `app/api/` Submodule

#### `routes.py`
- **What it does:** Defines the REST controller endpoints for the scanning pipeline (`/scan`, `/results/{domain}`, `/cbom/{domain}`, `/quantum-score/{domain}`). It defines an asynchronous background task `_run_scan_pipeline` that sequentially connects all the custom scanner modules and saves intermediate and final results to MongoDB.
- **Tools/Libraries used:** `FastAPI` (`APIRouter`, `BackgroundTasks`), `uuid` for generating scan identifiers, `asyncio` for executing the modular steps in concurrent tasks.

---

### `app/db/` Submodule

#### `connection.py`
- **What it does:** Manages an async connection lifecycle to MongoDB. Contains functions to connect `connect_db()`, disconnect `disconnect_db()`, and retrieve the active database instance reference `get_database()`.
- **Tools/Libraries used:** `motor.motor_asyncio` (`AsyncIOMotorClient`, `AsyncIOMotorDatabase`).

#### `models.py`
- **What it does:** Contains all Pydantic schemas (data models) and Enums representing the request payloads, response payloads, and internal structural representations (e.g., `TLSInfo`, `CryptoComponent`, `CBOMReport`, `QuantumScore`, `Recommendation`, `CVEFinding`).
- **Tools/Libraries used:** `pydantic` (`BaseModel`, `Field`), `typing` (`Enum`, `List`, `Optional`, `Dict`, `Any`).

---

### `app/modules/` Submodule

#### `asset_discovery.py`
- **What it does:** Performs initial target footprinting. It executes external OS-level reconnaissance commands as subprocesses to find subdomains inside a main domain, and then probes out their open ports. It has graceful fallback if the subsystem commands are absent.
- **Tools/Libraries used:** `asyncio.create_subprocess_exec` to execute shell commands asynchronously, `re` for extracting ports from grepable scan formats.
- **Commands used (via subprocess):**
  - `subfinder -d <domain> -silent` (subdomain enumeration)
  - `nmap -Pn -sT -p <ports> --open -oG - <target>` (port scanning)

#### `tls_scanner.py`
- **What it does:** Detailed inspection script for TLS vulnerabilities. Connects to hosts to evaluate TLS protocol support (individually validating TLS v1 to 1.3), enumerates available cipher suites, checks for forward-secrecy properties, and validates full certificate chain data as well as certificate expiration dates.
- **Tools/Libraries used:** Built-in Python `ssl` and `socket` modules, `cryptography.x509` (parsing raw certificates in binary DER format).

#### `crypto_analyzer.py`
- **What it does:** Normalizes internal raw data generated by the `tls_scanner.py`. It explicitly maps every negotiated and supported protocol version, cipher suite, key exchange mechanism, and signature algorithm into `CryptoComponent` formats with standardized qualitative risk rankings (`CRITICAL` up to `SAFE`) and flags quantum vulnerability states.
- **Tools/Libraries used:** Internal ruleset dictionaries and heuristics mappings.

#### `quantum_risk_engine.py` + `quantum_catalog.py` + `data/pqc_algorithm_catalog.json`
- **What it does:** Evaluates classified cryptographic components for PQC transition posture (Shor- and Grover-relevant families). Computes a Quantum Readiness Score (0–100) as a weighted mean of **per-category minima**, with optional estate vs per-host rollups. Loads a **versioned JSON catalog** for KEX/signature/hash/protocol string rules; exposes **confidence** (from TLS scan rows) and **drivers** for explainability.
- **Tools/Libraries used:** JSON catalog loader + Python heuristics (`quantum_catalog.load_catalog_dict`).
- **Deep dive:** [docs/quantum-risk-scoring-engine.md](docs/quantum-risk-scoring-engine.md) (formulas, rule order, aggregation, drivers, confidence).

#### `cbom_generator.py`
- **What it does:** Filters and aggregates the evaluated cryptographic component list into a formal `Cryptographic Bill of Materials` block. Deduplicates repetitive components, isolating only the ones with the highest risk profiles, and summarizes counts of algorithm deployments arrayed by risk level.
- **Tools/Libraries used:** Python's `collections.Counter` module for building frequency tables.

#### `recommendation_engine.py`
- **What it does:** Maps vulnerable (especially quantum-vulnerable) components against definitive mitigation and migration guidance. Produces specific post-quantum cryptography algorithm recommendations (e.g. replacing RSA/ECDH deployments with NIST's `CRYSTALS-Kyber` or `CRYSTALS-Dilithium`).
- **Tools/Libraries used:** Explicit matching strings and internal mapping directories based on modern PQC standards.

#### `headers_scanner.py`
- **What it does:** Uses direct HTTP calls to retrieve server headers and checks for 11 critical web security headers (HSTS, Content Security Policy, X-Frame-Options, etc.). It simultaneously searches for unauthorized information leakage (e.g. `Server`, `X-Powered-By`).
- **Tools/Libraries used:** Python's built-in `urllib.request` classes (`urlopen`, `Request`).

#### `cve_mapper.py`
- **What it does:** A static evaluation engine that compares identified TLS components and protocols against a database representing 17 explicit historical and modern security vulnerabilities (e.g., POODLE, Heartbleed, BEAST, FREAK, Sweet32, and DROWN attacks). Outputs any actionable `CVEFinding` objects.
- **Tools/Libraries used:** Lambda logic blocks stored inside dictionaries representing the vulnerability definitions.

---

### `app/utils/` Submodule

#### `logger.py`
- **What it does:** Implements centralized application console logging. Creates logger instances with uniform standardized formatting that dictates timestamp mapping, event risk levels, executing module designations, and output sequences.
- **Tools/Libraries used:** Built-in Python `logging` library mapping outputs directly to `sys.stdout`.


## Scanning Capabilities

### TLS & Cryptography
- ✅ All supported TLS protocol versions (tests 1.0, 1.1, 1.2, 1.3 individually)
- ✅ All supported cipher suites (enumerates every cipher, not just negotiated)
- ✅ Key exchange algorithm classification (RSA, ECDHE, DHE, etc.)
- ✅ Certificate signature algorithm analysis
- ✅ Certificate chain validation
- ✅ Certificate expiry alerts (30/60/90 day warnings)
- ✅ Self-signed certificate detection
- ✅ Forward secrecy detection
- ✅ Weak algorithm detection (MD5, SHA-1, RC4, DES, 3DES, NULL, EXPORT)

### Quantum Risk Assessment
- ✅ Quantum Readiness Score (0–100) with weighted breakdown
- ✅ Harvest-Now-Decrypt-Later (HNDL) threat flagging
- ✅ PQC migration recommendations (CRYSTALS-Kyber, Dilithium, Falcon, SPHINCS+)

**Limitations (align expectations with [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd)):** The score is a **heuristic** over externally observed TLS/CBOM signals (protocols, suites, cert chain metadata, string-level PQC hints). It is **not** proof of FIPS 203/204/205-validated modules in production, HSM key custody, or absence of downgrade / MITM. Hybrid KEX names from scans do not verify that a PQ KEM is negotiated end-to-end. Use the embedded **catalog version**, per-category breakdown, **confidence** (from TLS row quality), and **drivers** for audit narrative only—then validate with engineering and PKI owners.

### HTTP Security Headers
- ✅ Strict-Transport-Security (HSTS)
- ✅ Content-Security-Policy (CSP)
- ✅ X-Content-Type-Options
- ✅ X-Frame-Options
- ✅ X-XSS-Protection
- ✅ Referrer-Policy
- ✅ Permissions-Policy
- ✅ Cross-Origin-Opener-Policy / Resource-Policy
- ✅ Cache-Control
- ✅ Information leakage detection (Server, X-Powered-By, X-AspNet-Version)

### CVE / Known Attack Detection (17 Rules)

| CVE | Attack | Severity |
|---|---|---|
| CVE-2016-0800 | DROWN | CRITICAL |
| CVE-2014-0160 | Heartbleed (awareness) | CRITICAL |
| CVE-2014-3566 | POODLE | HIGH |
| CVE-2015-0204 | FREAK | HIGH |
| CVE-2015-4000 | Logjam | HIGH |
| CVE-2013-2566 | RC4 Bias | HIGH |
| CVE-2011-3389 | BEAST | MEDIUM |
| CVE-2016-2107 | AES-CBC Padding Oracle | MEDIUM |
| CVE-2016-6329 | Sweet32 | MEDIUM |
| QUANTUM-001 | Harvest Now, Decrypt Later | HIGH |
| FS-001 | No Forward Secrecy | HIGH |
| CERT-001/002 | Cert Expiry / Expired | MEDIUM/CRITICAL |
| CERT-003/004 | Self-Signed / Weak Key | HIGH |
| PROTO-001/002 | Legacy TLS 1.0/1.1 | HIGH/MEDIUM |

## Cross-Network Setup (Kali ↔ Windows)

The backend runs on **Kali Linux** and communicates with the React frontend on **Windows**.

1. Start the backend on Kali:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```
2. On Windows, configure the React frontend to point to `http://<kali-ip>:8000`
3. Use `CORS_ORIGINS=*` in `Backend/.env`, or add the Windows browser origin explicitly if not using `*`

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | FastAPI |
| Language | Python 3.11+ |
| Database | MongoDB (Motor async driver) |
| TLS Analysis | Python `ssl` + `cryptography` library |
| Asset Discovery | subfinder, nmap (via subprocess) |
| Frontend | React + Vite (in `../Frontend/`) |
