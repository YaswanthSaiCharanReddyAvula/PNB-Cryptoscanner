"""
QuantumShield — Safe Filesystem Traversal Subsystem

Recursively walks authorized filesystem roots with strict scope enforcement,
symlink safety, resource bounds, and file classification.
Never executes untrusted files or escapes authorized directories.
"""

from __future__ import annotations

import hashlib
import os
import stat
import time
from typing import List, Tuple

from app.scanner.container.filesystem.classifier import FileClassifier
from app.scanner.container.models import FileArtifact, ResourceLimits
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Standard directory exclusions to prevent infinite loops / noise
DEFAULT_SKIP_DIRS = frozenset({
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".tox", ".cache", "dist", "build", "site-packages",
    "proc", "sys", "dev", # Virtual Linux filesystems
})


class FilesystemTraversalError(Exception):
    """Raised when traversal fails security invariants."""
    pass


class SafeFilesystemWalker:
    """Safe, bounded filesystem walker."""

    def __init__(
        self,
        authorized_root: str,
        limits: ResourceLimits | None = None,
        skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS,
        follow_symlinks: bool = False,
    ):
        self.authorized_root = os.path.abspath(authorized_root)
        self.limits = limits or ResourceLimits()
        self.skip_dirs = skip_dirs
        self.follow_symlinks = follow_symlinks

        self.files_inspected = 0
        self.files_skipped = 0
        self.total_bytes_seen = 0
        self.symlink_count = 0
        self.events: list[str] = []
        self.errors: list[dict] = []

    def walk(self, sub_scope: str = "") -> List[FileArtifact]:
        """
        Walk the authorized directory tree, yielding or returning FileArtifacts.
        If sub_scope is provided, bounds search to authorized_root / sub_scope.
        """
        start_time = time.monotonic()
        target_path = self.authorized_root
        if sub_scope:
            candidate = os.path.abspath(os.path.join(self.authorized_root, sub_scope.lstrip("/\\")))
            # Verify sub_scope does not escape authorized root
            if not self._is_within_root(candidate, self.authorized_root):
                msg = f"SCOPE_VIOLATION: Sub-scope '{sub_scope}' escapes authorized root '{self.authorized_root}'"
                self.events.append(msg)
                logger.warning(msg)
                return []
            target_path = candidate

        if not os.path.exists(target_path):
            logger.info("Target path does not exist: %s", target_path)
            return []

        # Single file check
        if os.path.isfile(target_path):
            artifact = self._process_file(target_path, self.authorized_root)
            return [artifact] if artifact else []

        artifacts: List[FileArtifact] = []

        for root, dirs, files in os.walk(target_path, topdown=True, followlinks=False):
            # Check time limit
            if time.monotonic() - start_time > self.limits.max_scan_time_seconds:
                self.events.append(f"RESOURCE_LIMIT_EXCEEDED: max_scan_time_seconds ({self.limits.max_scan_time_seconds}s)")
                logger.warning("Filesystem traversal exceeded time limit")
                break

            # Check directory depth
            rel_dir = os.path.relpath(root, self.authorized_root)
            depth = 0 if rel_dir == "." else len(rel_dir.replace("\\", "/").split("/"))
            if depth >= self.limits.max_directory_depth:
                self.events.append(f"DEPTH_LIMIT_REACHED: depth {depth} at {rel_dir}")
                dirs[:] = []
                continue

            # Prune skipped directory names
            dirs[:] = [d for d in dirs if d.lower() not in self.skip_dirs]

            # Enforce symlink safety for directories
            safe_dirs = []
            for d in dirs:
                dir_path = os.path.join(root, d)
                if os.path.islink(dir_path):
                    self.symlink_count += 1
                    if not self.follow_symlinks:
                        self.events.append(f"SYMLINK_SKIPPED_POLICY: Directory symlink skipped at {dir_path}")
                        continue
                    real_dir = os.path.realpath(dir_path)
                    if not self._is_within_root(real_dir, self.authorized_root):
                        self.events.append(f"SYMLINK_SKIPPED_OUT_OF_SCOPE: {dir_path} -> {real_dir}")
                        continue
                safe_dirs.append(d)
            dirs[:] = safe_dirs

            for filename in files:
                # File count limit check
                if self.files_inspected >= self.limits.max_file_count:
                    self.events.append(f"RESOURCE_LIMIT_EXCEEDED: max_file_count ({self.limits.max_file_count})")
                    logger.warning("Filesystem traversal reached max_file_count limit")
                    return artifacts

                file_path = os.path.join(root, filename)
                artifact = self._process_file(file_path, self.authorized_root)
                if artifact:
                    artifacts.append(artifact)

        return artifacts

    def _process_file(self, file_path: str, base_root: str) -> FileArtifact | None:
        """Inspect a single file entry safely."""
        try:
            is_symlink = os.path.islink(file_path)
            symlink_target = None

            if is_symlink:
                self.symlink_count += 1
                try:
                    symlink_target = os.readlink(file_path)
                    real_path = os.path.realpath(file_path)
                    if not self._is_within_root(real_path, self.authorized_root):
                        self.files_skipped += 1
                        self.events.append(f"SYMLINK_SKIPPED_OUT_OF_SCOPE: {file_path} -> {real_path}")
                        return None
                    if not self.follow_symlinks:
                        # Inspect symlink itself without reading target
                        pass
                except OSError as exc:
                    self.files_skipped += 1
                    self.errors.append({"path": file_path, "error": str(exc)})
                    return None

            try:
                st = os.stat(file_path)
            except OSError as exc:
                self.files_skipped += 1
                self.errors.append({"path": file_path, "error": str(exc)})
                return None

            # Skip special files: sockets, fifos, block/char devices
            mode = st.st_mode
            if stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
                self.files_skipped += 1
                self.events.append(f"SPECIAL_FILE_SKIPPED: {file_path}")
                return None

            size = st.st_size
            self.total_bytes_seen += size
            self.files_inspected += 1

            # Permissions
            is_world_readable = bool(mode & stat.S_IROTH)
            is_world_writable = bool(mode & stat.S_IWOTH)

            # Classify
            file_type, extra = FileClassifier.classify(file_path, size)

            # Calculate SHA-256 for relevant files (certs, keys, configs, packages)
            sha256_hash = None
            if size <= self.limits.max_file_size_bytes and file_type in (
                "certificate", "private_key_candidate", "public_key", "keystore", "crypto_config", "package_metadata"
            ):
                sha256_hash = self._compute_sha256(file_path)

            rel_path = os.path.relpath(file_path, base_root).replace("\\", "/")

            return FileArtifact(
                file_path=file_path,
                relative_path=rel_path,
                size_bytes=size,
                file_type=file_type,
                is_symlink=is_symlink,
                symlink_target=symlink_target,
                permissions_mode=mode,
                is_world_readable=is_world_readable,
                is_world_writable=is_world_writable,
                sha256=sha256_hash,
            )

        except Exception as exc:
            self.files_skipped += 1
            self.errors.append({"path": file_path, "error": str(exc)})
            return None

    @staticmethod
    def _is_within_root(path: str, root: str) -> bool:
        """Verify that resolved canonical path resides inside canonical root."""
        norm_path = os.path.abspath(os.path.realpath(path))
        norm_root = os.path.abspath(os.path.realpath(root))
        try:
            common = os.path.commonpath([norm_path, norm_root])
            return common == norm_root
        except ValueError:
            # Different drives on Windows (e.g. C: vs A:)
            return False

    @staticmethod
    def _compute_sha256(filepath: str) -> str | None:
        """Stream compute SHA-256 of file in 64KB chunks."""
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None
