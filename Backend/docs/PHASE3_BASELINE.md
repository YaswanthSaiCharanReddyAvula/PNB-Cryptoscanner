# Phase 3 — Analysis depth (threat model, NIST mapping, simulation)

**Status:** Implemented in this branch.  
**Theme (PRD §11):** NIST/threat enrichment, quantum score what-if — **indicative**, not certification.

---

## 1. Backend

| Piece | Location | Role |
|-------|----------|------|
| CBOM enrichment | `app/modules/threat_nist_mapping.py` → `enrich_cbom_component_dict` | Adds `threat_vector`, `nist_primary_recommendation`, `nist_summary`, `nist_reference_urls` to each component. |
| CBOM API | `GET /api/v1/cbom/per-app` | Returns enriched components (used by CBOM + Crypto Findings UIs). |
| Threat summary | `GET /api/v1/threat-model/summary` | Static vector definitions + **counts from latest completed scan** (legacy TLS, RSA mentions, hybrid signals). |
| NIST catalog | `GET /api/v1/threat-model/nist-catalog` | Static FIPS 203/204/205 + SP 800-208 URLs. |
| Score simulation | `POST /api/v1/quantum-score/simulate` | Heuristic delta on engine 0–100 score; returns `assumptions`, `note`, `nist_pqc_references`. |
| Export bundle | `GET /api/v1/reports/export-bundle` | Includes `threat_nist_context` pointer to publications. |

---

## 2. Frontend

| Page | Phase 3 behavior |
|------|------------------|
| **Crypto Findings** | Threat-model summary strip (scan-aware counts + vector reference). Table columns: **Threat** (Shor/Grover/HNDL), **NIST focus** (primary recommendation). Detail sheet: NIST summary text + outbound links. |
| **CBOM** | Already surfaces `threat_vector` + `nist_primary_recommendation` in the per-component table (unchanged). |
| **Cyber Rating** | What-if simulation shows **assumptions** applied and **NIST publication links** returned by the API. |

---

## 3. Phase 3 exit criteria

- [x] Enriched CBOM payload consumed in product UI (Findings + CBOM).
- [x] Threat model summary + NIST catalog reachable from Crypto Findings.
- [x] Simulation API response fully reflected in Cyber Rating (scores + qualifiers + refs).
- [x] Copy consistently states **heuristic / indicative** (not formal risk or compliance proof).

---

*Update when adding new threat vectors, changing `enrich_cbom_component_dict` output shape, or altering simulation math.*
