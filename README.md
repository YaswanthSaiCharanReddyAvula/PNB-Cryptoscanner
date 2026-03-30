## QuantumShield — Quantum‑Safe Cryptography Migration Platform (PNB Hackathon 2026)

QuantumShield helps enterprises prepare for **cryptographically relevant quantum computers** by turning today’s TLS/crypto posture into an actionable **PQC migration roadmap**.

It combines:

- automated crypto/TLS **audit** across discovered assets
- a **Cryptographic Bill of Materials (CBOM)** for visibility and evidence
- a **quantum readiness / cyber rating** with explainability
- a **Security Roadmap** (risk → target solution + actions)
- **governance orchestration** (migration tasks + waivers + approval workflow)

---

## Problem statement

Most enterprises (banks, fintech, critical infra) still rely on cryptography that will be broken by quantum attacks:

- **Shor’s algorithm** breaks widely deployed public‑key crypto (RSA, ECDH/ECC).
- Even before quantum computers arrive, attackers can do **Harvest‑Now‑Decrypt‑Later (HNDL)** by collecting encrypted traffic today and decrypting later once quantum is viable.

Organizations have three practical challenges:

- **Discovery gap**: they don’t know where crypto is used (shadow subdomains, non‑standard ports, unknown TLS terminators).
- **Evidence gap**: security teams can’t prove which endpoints are vulnerable and why.
- **Execution gap**: even with findings, there’s no coordinated phased plan (what to fix first, who owns it, what exceptions are allowed, how to track progress).

---

## Existing solutions & why they are not enough

### What exists today

- **TLS scanners / vulnerability scanners** (Nmap scripts, testssl.sh, SSL Labs)
- **Asset discovery tooling** (subdomain enumeration, port scanners)
- **PKI / certificate dashboards**
- **Compliance checklists / PDFs**

### Gaps in those approaches

- **Not PQC‑oriented**: they flag TLS issues but don’t translate results into **PQC migration actions** aligned to NIST PQC (ML‑KEM / ML‑DSA / SLH‑DSA).
- **Fragmented**: discovery, TLS analysis, scoring, and remediation tracking live in different tools.
- **Low explainability**: you get a score or a finding, but not a governance‑ready trail of evidence and drivers.
- **No orchestration**: teams still manage migration in spreadsheets with no waiver/approval workflow.

---

## Proposed solution (QuantumShield)

QuantumShield is an end‑to‑end platform that:

1. **Discovers assets** (subdomains + services + ports)
2. **Inspects TLS posture** (protocols, cipher suites, key lengths, certificate signals)
3. **Builds a CBOM** (crypto inventory + risk classification)
4. **Scores quantum readiness** (0–1000 cyber rating) with explainability drivers
5. **Generates a Security Roadmap** (Critical → Legacy → Standard → Elite tier journey + actions)
6. **Orchestrates execution** via Migration Planner (tasks + waivers + approvals)

---

## Novelty (what’s different)

- **Roadmap, not just findings**: outputs a staged tier journey and concrete target solutions (e.g., “TLS 1.3 everywhere”, “pilot hybrid KEM”, “replace RSA key exchange”).
- **Explainability-first**: cyber rating includes “why this tier” evidence counts and drivers; roadmap items include confidence.
- **Governance built‑in**: migration tasks + waiver queue (with Admin approval) to support enterprise exception management.
- **Historical viewing**: security roadmap can be viewed for **previous scans** (not only latest), enabling trend comparison.

---

## Architecture

```mermaid
flowchart LR
  FE[Frontend (React + Vite)] -->|REST + WebSocket| BE[Backend (FastAPI)]
  BE -->|store| M[(MongoDB: scans, assets, tls_results, cbom)]
  BE --> Tools[Linux tools: subfinder, nmap, testssl.sh, ...]
  FE -->|Exports| PDF[Client-side PDF/CSV/JSON]
```

### Key modules (backend)

- **Asset discovery**: enumerates subdomains + probes services + ports
- **TLS scanner**: captures TLS versions / cipher suites / cert metadata (with timeouts)
- **Crypto analyzer + quantum engine**: classifies algorithms, assesses risk, derives score
- **Security roadmap builder**: transforms scan data into tier journey + action rows
- **Migration planner**: tasks + waivers workflow tied back to scan evidence

---

## Impact

- **Security teams**: visibility + prioritization (what breaks under quantum, where HNDL exists)
- **Executives**: a single readiness score + roadmap, exportable for reporting
- **Engineers**: concrete, staged actions aligned to the organization’s posture and constraints
- **Governance**: controlled exceptions through waivers and approvals (audit trail)

---

## Scalability & enterprise readiness

- **Asynchronous pipeline**: long‑running scans don’t block the UI; progress streams via WebSocket.
- **Portfolio support**: batch scans and “Inventory Runs” allow multi‑domain monitoring.
- **Deduplication**: inventory endpoints dedupe hosts across scans and prefer newest results.
- **Controlled scanning**: Controller options allow caps on subdomains and execution time.

---

## Advantages

- **Single scan → multi‑page insights** (CBOM, posture, rating, roadmap)
- **Actionable output** aligned to PQC migration (not just passive reporting)
- **Explainable scoring** and confidence signaling
- **Governance workflow** built‑in

---

## Limitations & mitigations

- **Linux-only tooling**: scanners like `nmap`/`testssl.sh` run best on Linux.
  - **Mitigation**: run backend on Kali/Ubuntu VM; frontend can run on Windows/Vercel.
- **Geographic distribution**: currently a demo visualization unless you enrich IPs with GeoIP.
  - **Mitigation**: plug GeoIP enrichment into the pipeline (future enhancement).
- **PQC ecosystem is evolving**: hybrid KEM availability varies by client and TLS terminator.
  - **Mitigation**: roadmap marks items as indicative; encourages validation with platform owners.

---

## Demo walkthrough (5–7 minutes)

1. Login (Admin or Employee demo user)
2. On **Overview**, run a scan for a domain
3. Open:
   - **CBOM**: show inventory + export PDF
   - **Cyber Rating**: show score + “Why this tier”
   - **Security Roadmap**: show tier journey and actions; use “Past scans” to open history
   - **Migration Planner**: create task / request waiver; approve as Admin

---

## Quickstart (local)

### Backend

From `Backend/`:

```bash
python -m venv .venv
# activate it: Windows -> .venv\Scripts\activate | Linux -> source .venv/bin/activate
pip install -r requirements.txt

# copy env template
copy .env.example .env  # Windows
# cp .env.example .env  # Linux

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

- Swagger: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`

### Frontend

From `Frontend/`:

```bash
npm install

# create Frontend/.env.local
# VITE_API_BASE_URL=http://localhost:8000/api/v1

npm run dev
```

Open: `http://localhost:8080`

---

## Environment variables

### Backend (`Backend/.env`)

See `Backend/.env.example`. Common values:

- `MONGO_URI` / `MONGO_DB_NAME`
- `CORS_ORIGINS` (use `*` for hackathon/dev)
- `TESTSSL_TIMEOUT`

### Frontend (`Frontend/.env.local`)

See `Frontend/.env.example`.

- `VITE_API_BASE_URL` must end with `/api/v1`

---

## Demo login & RBAC

- **Admin**: `scanner@example.com / pass123`
- **Employee**: `employee@example.com / pass123`

Admin capabilities (examples):

- approve / reject waivers
- delete waivers/tasks
- seed tasks from latest scan backlog

---

## Pages

- **Overview** (`/`): scan initiation + KPIs + live pipeline
- **Inventory Runs** (`/inventory-runs`): recent scan jobs (filter/sort)
- **Inventory Assets** (`/inventory`): deduped assets across scans
- **CBOM** (`/cbom`): CBOM charts + exports (JSON/CSV/PDF)
- **PQC Posture** (`/pqc-posture`)
- **Cyber Rating** (`/cyber-rating`): score + “Why this tier”
- **Security Roadmap** (`/security-roadmap`)
  - loads latest completed scan by default
  - can load **previous scans** via “Past scans” selector
- **Migration Planner** (`/migration`): tasks + waivers queue
- **Policy & Standards** (`/policy`): admin to save
- **Admin & Reporting** (`/admin`): admin controls (demo)

---

## Key API endpoints

- Scan
  - `POST /api/v1/scan`
  - `POST /api/v1/scan/batch`
- Results
  - `GET /api/v1/results/{domain}`
- Portfolio
  - `GET /api/v1/scans/recent`
  - `GET /api/v1/scans/history?domain=...`
- Security Roadmap
  - `GET /api/v1/security-roadmap/latest`
  - `GET /api/v1/security-roadmap/{domain}`
  - `GET /api/v1/security-roadmap/scan/{scan_id}` (historical)
- Inventory (manual add)
  - `POST /api/v1/inventory/sources/import` (source=`manual`)

---

## Exports

- **CBOM PDF** is generated client-side from CBOM table data (not a print screenshot).
- **Server bundle**: `GET /api/v1/reports/export-bundle` (JSON).

---

## Troubleshooting

- **New endpoints not found**: restart backend (uvicorn) after pulling changes.
- **CORS issues**: set `CORS_ORIGINS=*` for dev.
- **No data**: run at least one completed scan from Overview.

