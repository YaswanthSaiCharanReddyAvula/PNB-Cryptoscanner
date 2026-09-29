# Crypto Analysis Engine Architecture

```text
                  ┌──────────────────────┐
                  │   TLSCryptoEngine    │
                  │                      │
                  │ Protocol observation │
                  │ Cipher observation   │
                  │ Certificate capture  │
                  │ PQC signals          │
                  │ KEX observation      │
                  └──────────┬───────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │    TLSProfile   │
                    └────────┬────────┘
                             │
                             ▼
              ┌────────────────────────────┐
              │   CryptoAnalysisEngine     │
              │                            │
              │ Algorithm normalization    │
              │ Cipher analysis            │
              │ Key-strength analysis      │
              │ Certificate-chain analysis │
              │ Hash analysis              │
              │ KEX analysis               │
              │ Forward secrecy            │
              │ Quantum risk               │
              │ HNDL                       │
              │ PQC/hybrid verification    │
              │ Severity                   │
              │ Evidence                   │
              │ Recommendations            │
              └─────────────┬──────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ CryptoFinding │
                    └───────┬───────┘
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
           CBOM           Risk          Migration
             │              │              │
             └──────────────┼──────────────┘
                            ▼
                     Dashboard / API
```

## Responsibilities
- **Observe first**: `TLSCryptoEngine` extracts facts.
- **Interpret second**: `CryptoAnalysisEngine` deterministically applies the risk taxonomy.
- **Recommend third**: Finds vulnerabilities and suggests mitigations via `CryptoFinding`.
