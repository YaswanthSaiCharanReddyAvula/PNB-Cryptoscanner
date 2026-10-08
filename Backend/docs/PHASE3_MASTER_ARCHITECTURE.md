# PHASE 3 MASTER ARCHITECTURE

## 1. CURRENT ARCHITECTURE (As Implemented)

Currently, the Phase 3 (Data Convergence & Standardization) architecture operates as follows:

```text
       Raw Scanners (Recon, Network, TLS, etc.)
                   │
                   ▼
              ScanContext
                   │
                   ▼
         Convergence Adapters
 (Directly construct CanonicalAsset & map props)
                   │
                   ▼
         Deduplication Engine
 (Merges assets by ID, shallow overwrites properties)
                   │
                   ▼
         Correlation Engine
 (Links certificates to keys, hostnames to IPs)
                   │
                   ▼
         Aggregation Engine
 (Builds CanonicalEstate by sorting/categorizing)
                   │
                   ▼
            CycloneDX Exporter
 (Reads CanonicalEstate and manually extracts properties)
```

**Known Deficiencies in Current Architecture:**
1. **Property Overwrites**: Conflicting properties from different engines overwrite each other due to a shallow `.update()` dictionary merge.
2. **Missing Observation Layer**: Adapters bypass an immutable `Observation` layer and write directly to the CanonicalAsset.
3. **Lossy CycloneDX Export**: Properties not explicitly coded into `crypto_mapper.py` are discarded during CBOM generation.
4. **Legacy Shadow Paths**: Track C (`cbom_unification.py`) and Reporting (`reporting.py`) construct their own CBOM and Annexure-A reports bypassing `CanonicalEstate`.

---

## 2. TARGET ARCHITECTURE (Master Principle)

The future target architecture strictly separates concerns from Discovery through Export, establishing a single source of truth without destructive merging.

```text
                      EXISTING SCANNERS
                             │
                             ▼
                    CANONICAL OBSERVATION
            (Immutable raw facts, state, evidence)
                             │
                             ▼
                    IDENTITY RESOLUTION
            (Determines canonical asset ownership)
                             │
                             ▼
                     PROPERTY MAPPING
             (Attaches properties based on registry)
                             │
                             ▼
                       NORMALIZATION
             (Standardizes values: IP, Version, etc.)
                             │
                             ▼
                    PROPERTY RESOLUTION
            (Handles conflicts, defines precedence)
                             │
                             ▼
                        ASSET GRAPH
             (Canonical assets, properties, relations)
                             │
                             ▼
                    FINDING CORRELATION
               (Links vulnerabilities to assets)
                             │
                             ▼
                    CANONICAL INVENTORY
                  (SINGLE SOURCE OF TRUTH)
                             │
             ┌───────────────┼───────────────┐
             ▼               ▼               ▼
           RISK           QUANTUM        MIGRATION
             │               │               │
             └───────────────┼───────────────┘
                             ▼
                         EXPORTERS
                    (CycloneDX, Annexure-A)
                             │
                             ▼
                         API / DB
                             │
                             ▼
                         FRONTEND
```

**Core Directives for the Target Architecture:**
- **Observations are immutable.** A normalized canonical value never deletes the raw observation it came from.
- **Resolution is non-destructive.** Conflicting properties are preserved side-by-side with conflict metadata, while a canonical priority rule decides the winner.
- **Single Source of Truth.** Exporters, APIs, and Risk engines must consume the `CanonicalInventory`. Duplicate models (like `UnifiedCBOM`) will be deprecated.
