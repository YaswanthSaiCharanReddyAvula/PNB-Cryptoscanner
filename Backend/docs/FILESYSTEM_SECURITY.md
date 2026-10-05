# Filesystem Inspection Security Controls
## ECDAT / QuantumShield Container & Filesystem Inspection Engine

### 1. Scope Enforcement
The engine operates strictly within authorized filesystem roots:
- `authorized_root` is canonicalized via `os.path.realpath`.
- Sub-scopes (e.g. `/src/crypto`) are validated before descent.
- Any attempt to reference a path outside `authorized_root` (via `../`, absolute links, or volume mounts) is rejected immediately with `SCOPE_VIOLATION`.

### 2. Symlink Safety & Out-of-Scope Protection
Symlinks are treated as untrusted pointers:
- By default, symlinks are never followed blindly (`follow_symlinks=False`).
- Directory symlinks are skipped with `SYMLINK_SKIPPED_POLICY`.
- When symlink target resolution is enabled, `os.path.realpath(link)` is verified against `authorized_root`.
- If a symlink points outside the authorized root, it is skipped and logged as `SYMLINK_SKIPPED_OUT_OF_SCOPE`.
- Symlink loop detection prevents recursive infinite cycles.
- Maximum symlink count limit (`max_symlink_count = 5000`) prevents denial of service.

### 3. Archive & Decompression Bomb Defenses
Untrusted `.tar` and `.tar.gz` archives undergo strict pre-extraction checks:
- **Path Traversal Defense**: All member names are stripped of leading slashes, drive letters, and checked against `..` tokens.
- **Decompression Ratio**: Rejects decompression ratios exceeding 20x when total bytes exceed 50MB.
- **Quotas**:
  - `max_archive_size_bytes = 1GB`
  - `max_extracted_size_bytes = 3GB`
  - `max_file_count = 50,000`
  - `max_file_size_bytes = 50MB`
- Any breach triggers `ArchiveSecurityError` and emits `RESOURCE_LIMIT_EXCEEDED` safely without crashing the scan pipeline.

### 4. Special Files & Permissions Isolation
- Sockets, FIFOs, block devices, and character devices are strictly ignored.
- File permissions are audited non-destructively:
  - World-readable private keys (`stat.S_IROTH`)
  - World-writable configuration files (`stat.S_IWOTH`)
