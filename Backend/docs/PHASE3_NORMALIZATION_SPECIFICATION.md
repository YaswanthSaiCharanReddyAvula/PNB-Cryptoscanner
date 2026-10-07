# Phase 3: Normalization Specification

## Rules
Data extracted from scan engines varies wildly in format (e.g., `Example.COM`, `https://example.com`, `example.com:443`). The normalization layer sanitizes inputs to enable deduplication.

### 1. Hostnames
- Lowercased.
- Stripped of protocol schemes (`https://`).
- Stripped of port numbers (if not explicitly tracking service identities).
- Stripped of trailing dots.

### 2. IP Addresses
- Parsed via `ipaddress` to enforce canonical string representation (removes leading zeroes, expands/collapses IPv6 correctly).

### 3. URLs
- Scheme and netloc lowercased.
- Ports standardized.
- Default path `/` enforced if missing when strictly required.

### 4. Ports
- Represented as a `(port, transport)` tuple where transport is normalized (e.g., `tcp`, `udp`).

### 5. Technologies & Algorithms
- Lowercased.
- Stripped of whitespace.
- Delegated to existing `crypto_normalization.py` for standardizing NIST curves vs SECG curves (e.g. `prime256v1` -> `secp256r1`).
