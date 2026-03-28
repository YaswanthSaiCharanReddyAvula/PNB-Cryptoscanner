# Product Requirements Document (PRD)

## QuantumShield — Quantum-Safe Cryptographic Assessment System

| Document | |
|----------|---|
| **Product name** | QuantumShield (PNB Crypto Scanner) |
| **Context** | PNB Cybersecurity Hackathon 2026 |
| **Version** | 1.0 |
| **Status** | As-implemented baseline (living document) |

---

## 1. Executive summary

QuantumShield is a **web application** that helps security and infrastructure teams **discover internet-facing assets**, **inspect TLS and cryptographic configurations**, **build a Cryptographic Bill of Materials (CBOM)**, **score quantum-era readiness**, and **plan Post-Quantum Cryptography (PQC) migration**—with dashboards, exports, and optional governance features (policy, webhooks, migration tasks, waivers).

The solution ships as a **FastAPI backend** (async scan pipeline, MongoDB persistence, WebSocket progress) and a **React (Vite) dashboard** (protected routes, real-time API status, charts and tables).

---

## 2. Vision and goals

### 2.1 Vision

Give organizations **continuous visibility** into **how cryptography is deployed** across their public footprint and **how prepared** they are for **quantum-era threats** (e.g., harvest-now–decrypt-later) and **NIST-aligned PQC** adoption—without replacing formal audits, but **accelerating prioritization** and **communication** with leadership.

### 2.2 Primary goals

1. **Discover** subdomains and services relevant to TLS/crypto assessment (within configurable limits).
2. **Measure** TLS versions, ciphers, certificates, headers, and algorithm-level risk via CBOM.
3. **Score** quantum readiness (0–100 engine scale surfaced in UI as needed) and **recommend** migration-oriented actions.
4. **Report** results in the UI and via **structured JSON exports** for demos and integration.
5. **Scale to portfolio use** via batch scans, scan history/diff, and inventory views (subject to concurrency caps).

### 2.3 Non-goals (explicit)

- **Not** a full SIEM, GRC suite, or certificate lifecycle manager.
- **Not** a guarantee of “quantum safety”; scores and simulations are **heuristic** and labeled as such where applicable.
- **Not** unlimited offensive scanning; subdomain counts, batch sizes, and concurrent scans are **capped** for stability and responsible use.

---

## 3. Target users and personas

| Persona | Needs |
|---------|--------|
| **Security analyst** | Run scans, review TLS/CBOM/CVE signals, track posture over time. |
| **Infrastructure / platform owner** | See per-host posture, metadata (owner/env/criticality), migration backlog. |
| **Security leadership** | Cyber rating, threat-model summary, export bundle for reporting. |
| **Admin (demo)** | Org crypto policy, outbound notifications, migration tasks/waivers, export audit trail. |

**Authentication model (current):** JWT-style session after login; roles exist in product concept (`admin`, `employee`); some admin APIs enforce `require_admin`.

---

## 4. Problem statement

Banks and large enterprises struggle to answer:

- **What cryptography is in use** across public endpoints and how **consistent** it is.
- **Which endpoints** are weakest against **legacy TLS**, weak ciphers, or **certificate** issues.
- **How to prioritize** PQC-related work given **NIST PQC** standards and internal constraints.

QuantumShield addresses this by **automating discovery + inspection**, **normalizing results into a CBOM**, and **tying recommendations** to scan evidence.

---

## 5. Product scope

### 5.1 In scope (implemented or specified in codebase)

| Area | Capability |
|------|------------|
| **Scanning** | Single-domain scan; optional batch scan (`MAX_BATCH_DOMAINS`); global concurrency limit (`MAX_CONCURRENT_SCANS`). |
| **Pipeline** | Eight stages: asset discovery → TLS → crypto analysis → quantum risk → CBOM → recommendations → HTTP headers → CVE/attack mapping (see Backend README). |
| **Real-time UX** | WebSocket updates during scan. |
| **Data** | MongoDB for scan documents and supporting collections (metadata, policy, integrations, tasks, waivers, export audit). |
| **Dashboards** | Dashboard summary, asset inventory, asset discovery (graph/tab views), CBOM, PQC posture, cyber rating, migration, admin. |
| **Portfolio** | Scan history, scan diff, inventory summary, asset metadata CRUD, registered inventory import, optional SBOM ingest, scan-time merge of registered/seed hosts. |
| **Exports & reporting** | Export bundle JSON; reporting domains/generate; migration roadmap; threat-model summary + NIST catalog; quantum score **simulation** (what-if). |
| **Governance** | Org crypto policy, integration settings (webhooks, masked URLs), migration tasks CRUD + seed-from-backlog, waivers workflow, export history. |
| **Ops** | Health check, rate limiting, CORS configuration, optional DB wipe/reset in dev. |

### 5.2 Out of scope / future

- Production-grade SSO, full RBAC UI parity, and hardened secret management (hackathon/demo assumptions may apply).
- Replacing external CT logs or commercial ASM for discovery beyond integrated tools.

---

## 6. User journeys

### 6.1 Primary: assess a domain

1. User signs in.
2. User starts a scan for a domain from the dashboard.
3. User observes live progress (WebSocket).
4. User reviews **CBOM**, **PQC Posture**, and **Cyber Rating** for the latest completed scan.
5. Optional: user downloads or consumes **export bundle** JSON for reporting.

### 6.2 Portfolio: multiple domains

1. User queues **batch scan** (within limits).
2. User polls results or uses **scan history** per domain.
3. User compares two scans via **scan diff** (hosts added/removed, TLS deltas).

### 6.3 Governance

1. Admin sets **org crypto policy** and **notification** endpoints.
2. User or admin manages **migration tasks** and **waivers**.
3. Stakeholders review **export audit** history.

---

## 7. Functional requirements

### 7.1 Scanning and results

- **FR-SCAN-1:** System SHALL accept a scan request with domain and optional parameters (subdomains, ports) and persist a scan record with status lifecycle (`pending` → `running` → `completed` / `failed`).
- **FR-SCAN-2:** System SHALL enforce a **maximum batch size** for multi-domain requests and a **global concurrent scan** limit.
- **FR-SCAN-3:** System SHALL expose full results by domain, including TLS results, CBOM, quantum score, recommendations, headers, and CVE mappings as produced by the pipeline.
- **FR-SCAN-4:** System SHALL merge **asset metadata** (owner, environment, criticality) from inventory when present.

### 7.2 CBOM and cryptography visibility

- **FR-CBOM-1:** System SHALL provide CBOM **summary**, **per-component** lists (with enrichment for threat/NIST context where implemented), and **chart** data (key lengths, CAs, protocols, cipher usage).
- **FR-CBOM-2:** CBOM views SHALL support filtering by **domain** when query parameters are used (latest completed scan for that domain).

### 7.3 Quantum readiness and PQC

- **FR-PQC-1:** System SHALL compute and store a **quantum score** and risk level with the scan.
- **FR-PQC-2:** System SHALL expose **PQC posture** derived from latest scan (per-asset grades, counts, recommendations snippets).
- **FR-PQC-3:** System SHALL expose **simulation** endpoint to project score under stated assumptions (TLS 1.3 everywhere, PQC hybrid KEM), with **disclaimer** that it is heuristic.

### 7.4 Cyber rating and threat model

- **FR-CR-1:** System SHALL expose an **enterprise cyber rating** scaled for UI (e.g., 0–1000) with tier labels and per-endpoint contributions where applicable.
- **FR-TM-1:** System SHALL expose **threat-model summary** (e.g., Shor/Grover/HNDL framing) and **NIST PQC reference** catalog URLs.

### 7.5 Migration and roadmap

- **FR-MIG-1:** System SHALL expose a **migration roadmap** derived from scan signals (phased waves / backlog concept).
- **FR-MIG-2:** System SHALL support **migration tasks** (list/create/update/delete, seed from backlog) and **waivers** lifecycle.

### 7.6 Portfolio and inventory

- **FR-INV-1:** System SHALL list **recent scans** per domain and **diff** two scans.
- **FR-INV-2:** System SHALL provide **deduplicated host inventory** across recent completed scans with optional metadata overlay.
- **FR-INV-3:** System SHALL support **bulk registration** of external asset rows (CMDB/cloud/K8s/Git-style `source` labels), optional **SBOM JSON** storage per host, and **scan-time merge** of registered or explicitly seeded hostnames into discovery.

### 7.7 Administration and integrations

- **FR-ADM-1:** System SHALL allow **org policy** read/update (admin).
- **FR-ADM-2:** System SHALL store **integration** settings (webhooks) and **mask** secrets in read APIs.
- **FR-ADM-3:** System SHALL **notify** outbound webhook on scan completion when enabled.
- **FR-ADM-4:** System SHALL maintain **export audit** history.

### 7.8 Authentication and authorization

- **FR-AUTH-1:** System SHALL authenticate users via **login** issuing a JWT-style token.
- **FR-AUTH-2:** Protected routes and selected APIs SHALL require a valid user; admin-only operations SHALL require admin role.

### 7.9 Frontend application

- **FR-FE-1:** Application SHALL provide routes: Dashboard, Asset Inventory, Asset Discovery, CBOM, PQC Posture, Cyber Rating, Executive brief (Phase 6), Reporting (if enabled), Admin, Migration.
- **FR-FE-2:** Application SHALL show **API connectivity** state to the backend.
- **FR-FE-3:** Unauthenticated users SHALL be redirected to login.

---

## 8. Non-functional requirements

| ID | Category | Requirement |
|----|----------|---------------|
| **NFR-1** | Performance | Scan runtime bounded by configurable timeouts; long work offloaded from request thread via background tasks. |
| **NFR-2** | Scalability | Configurable caps: `MAX_SUBDOMAINS`, `MAX_BATCH_DOMAINS`, `MAX_CONCURRENT_SCANS`. |
| **NFR-3** | Security | Rate limiting on API; JWT secret from environment; CORS aligned with browser rules (wildcard disables credentialed CORS). |
| **NFR-4** | Observability | Structured logging; health endpoint for liveness. |
| **NFR-5** | Deployability | Backend bind `0.0.0.0` for VM scenarios; frontend configurable `VITE_API_BASE_URL`. |
| **NFR-6** | Dependencies | Optional external tools (subfinder, nmap) with graceful degradation when missing. |

---

## 9. Technical architecture (summary)

| Layer | Technology |
|-------|------------|
| **Frontend** | React, TypeScript, Vite, Tailwind, shadcn/ui, Recharts, Axios, React Router |
| **Backend** | FastAPI, Uvicorn, Motor/PyMongo (async MongoDB), SlowAPI rate limit |
| **Realtime** | WebSocket (`/api/v1` ws module) |
| **Storage** | MongoDB (primary for scans and app data) |

*Note: Root README mentions PostgreSQL in diagrams; the implemented lifespan in `main.py` emphasizes MongoDB—treat PostgreSQL as optional/planned unless wired in branch.*

---

## 10. API surface (representative)

All routes are under the configured API prefix (e.g. `/api/v1`). Representative groups:

- **Scanner:** `POST /scan`, `POST /scan/batch`, `GET /results/{domain}`
- **Dashboard:** `GET /dashboard/summary`, `GET /dashboard/executive-brief` (Phase 6), `GET /dashboard/ops-snapshot` (Phase 7, admin), assets/stats/distribution, `GET /discovery/*`
- **CBOM:** `GET /cbom/summary`, `/cbom/per-app`, `/cbom/charts`, `/cbom/{domain}`
- **PQC / rating:** `/pqc/*`, `/cyber-rating`, `/cyber-rating/risk-factors`, `POST /quantum-score/simulate`
- **Portfolio:** `/scans/history`, `/scans/diff`, `/inventory/summary`, `/inventory/sources/import`, `/inventory/registered`, `/inventory/sbom`, `/assets/metadata`
- **Reports / threat / migration:** `/reports/export-bundle`, `/migration/roadmap`, `/threat-model/*`
- **Admin:** `/admin/policy`, `/admin/integrations`, `/admin/exports/history`, `/migration/tasks*`, `/migration/waivers*`
- **Auth:** `POST /auth/login`
- **System:** `/health`, dev-only reset/wipe (guarded usage)

Refer to OpenAPI at `/docs` on a running backend for the authoritative contract.

---

## 11. Phased roadmap (aligned with codebase comments)

| Phase | Theme | Examples |
|-------|--------|----------|
| **Phase 2** | Portfolio | Batch scans, concurrency gate, inventory, metadata |
| **Phase 3** | Analysis depth | NIST/threat enrichment, quantum simulation |
| **Phase 4** | Policy | Org crypto policy, integrations |
| **Phase 5** | Execution | Migration tasks, waivers, backlog seeding |
| **Phase 6** | Stakeholder reporting | `GET /dashboard/executive-brief`, print/JSON brief UI, export audit hooks |
| **Phase 7** | Operational visibility | `GET /dashboard/ops-snapshot` (admin), Mongo ping, queue counts, limits, failed-scan excerpts |

---

## 12. Success metrics (suggested)

| Metric | Description |
|--------|-------------|
| **Scan completion rate** | % of scans reaching `completed` vs `failed` (tool/timeout errors). |
| **Time-to-first-insight** | Time from scan start to first usable dashboard section. |
| **Coverage** | Hosts with TLS results vs discovered assets (pipeline health). |
| **User task success** | Users can find CBOM, PQC posture, and export bundle without support (hackathon eval). |

---

## 13. Risks and assumptions

- **Assumption:** Scans target **authorized** domains only; operators comply with organizational and legal scanning policies.
- **Risk:** External binaries (subfinder, nmap) vary by environment—results may differ between Windows dev and Kali production.
- **Risk:** Heuristic scores and simulations may be **misinterpreted** as formal risk—UI and API copy should keep **qualifiers** (product already notes simulation limitations in API intent).

---

## 14. Open questions

1. **Single source of truth** for API base path (`/api` vs `/api/v1`) across Frontend `.env` examples and deployment docs.
2. **PostgreSQL** usage: confirm whether it is required for any feature or documentation-only.
3. **Production** auth: replace demo login with IdP integration and full RBAC enforcement on all admin routes.
4. **Reporting PDF** mentioned in architecture diagrams: confirm if in scope or aspirational.

---

## Document control

This PRD reflects the **QuantumShield / PNB Crypto Scanner** repository as a **hackathon-grade** cryptographic assessment product. Update it when major features, endpoints, or deployment assumptions change.
