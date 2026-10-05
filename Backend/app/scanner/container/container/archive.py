"""
QuantumShield — Safe Archive Extraction Subsystem

Safely inspects and extracts untrusted container image archives (tar, tar.gz).
Protects against:
  - Path traversal (../, absolute paths, alternate drive letters)
  - Symlink / hardlink escape
  - Device nodes / FIFOs / sockets
  - Decompression bombs / zip bombs / tar bombs
  - Resource exhaustion
"""

from __future__ import annotations

import os
import tarfile
import tempfile
from typing import List, Optional

from app.scanner.container.models import ResourceLimits
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ArchiveSecurityError(Exception):
    """Raised when an archive violates safety invariants."""
    pass


class SafeArchiveExtractor:
    """Hardened archive inspector and extractor."""

    def __init__(self, limits: ResourceLimits | None = None):
        self.limits = limits or ResourceLimits()
        self.events: list[str] = []

    def safe_extract_tar(self, archive_path: str, destination_dir: str) -> List[str]:
        """
        Safely extract a tar archive into destination_dir with anti-traversal
        and decompression limits. Returns list of safely extracted filepaths.
        """
        dest_canonical = os.path.abspath(destination_dir)
        extracted_paths: List[str] = []

        if not os.path.exists(archive_path):
            raise ArchiveSecurityError(f"Archive file not found: {archive_path}")

        archive_size = os.path.getsize(archive_path)
        if archive_size > self.limits.max_archive_size_bytes:
            raise ArchiveSecurityError(
                f"RESOURCE_LIMIT_EXCEEDED: Archive size ({archive_size} bytes) exceeds limit ({self.limits.max_archive_size_bytes})"
            )

        total_extracted_bytes = 0
        file_count = 0

        try:
            with tarfile.open(archive_path, mode="r:*") as tar:
                # Pre-scan members for security
                for member in tar:
                    file_count += 1
                    if file_count > self.limits.max_file_count:
                        self.events.append(f"RESOURCE_LIMIT_EXCEEDED: max_file_count ({self.limits.max_file_count})")
                        raise ArchiveSecurityError("Tar bomb detected: exceeded max_file_count")

                    # Size check per file
                    if member.size > self.limits.max_file_size_bytes:
                        self.events.append(f"FILE_SKIPPED_SIZE: {member.name} ({member.size} bytes)")
                        continue

                    total_extracted_bytes += member.size
                    if total_extracted_bytes > self.limits.max_extracted_size_bytes:
                        self.events.append("RESOURCE_LIMIT_EXCEEDED: max_extracted_size_bytes")
                        raise ArchiveSecurityError("Decompression bomb detected: total extracted bytes exceeded limit")

                    # Compression ratio check (for compressed tars)
                    if archive_size > 0:
                        ratio = total_extracted_bytes / archive_size
                        if ratio > self.limits.max_compression_ratio and total_extracted_bytes > 50 * 1024 * 1024:
                            self.events.append(f"RESOURCE_LIMIT_EXCEEDED: compression_ratio ({ratio:.1f})")
                            raise ArchiveSecurityError("Decompression bomb detected: excessive compression ratio")

                    # Verify path does not escape destination
                    sanitized_rel = self._sanitize_member_path(member.name)
                    if not sanitized_rel:
                        self.events.append(f"PATH_TRAVERSAL_REJECTED: {member.name}")
                        continue

                    target_file_path = os.path.abspath(os.path.join(dest_canonical, sanitized_rel))
                    if not self._is_within_root(target_file_path, dest_canonical):
                        self.events.append(f"PATH_TRAVERSAL_REJECTED: {member.name} -> {target_file_path}")
                        continue

                    # Reject dangerous member types (char, block, fifo)
                    if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                        self.events.append(f"SPECIAL_DEVICE_SKIPPED: {member.name}")
                        continue

                    # Symlinks & hardlinks checks
                    if member.issym() or member.islnk():
                        link_target = member.linkname
                        # Check whether link points outside
                        if link_target.startswith("/") or link_target.startswith("\\") or ".." in link_target:
                            resolved_link = os.path.abspath(os.path.join(os.path.dirname(target_file_path), link_target))
                            if not self._is_within_root(resolved_link, dest_canonical):
                                self.events.append(f"SYMLINK_ESCAPE_REJECTED: {member.name} -> {link_target}")
                                continue

                    # Extract safely
                    try:
                        tar.extract(member, path=dest_canonical, set_attrs=False)
                        extracted_paths.append(target_file_path)
                    except Exception as exc:
                        self.events.append(f"MEMBER_EXTRACT_ERROR: {member.name}: {str(exc)}")

        except (tarfile.TarError, EOFError) as exc:
            self.events.append(f"CORRUPT_ARCHIVE_ERROR: {str(exc)}")
            logger.warning("Error reading archive %s: %s", archive_path, exc)

        return extracted_paths

    @staticmethod
    def _sanitize_member_path(member_name: str) -> Optional[str]:
        """Normalize and strip risky path elements."""
        cleaned = member_name.replace("\\", "/").strip()
        # Strip leading slashes and drive letters
        while cleaned.startswith("/"):
            cleaned = cleaned[1:]
        if len(cleaned) > 1 and cleaned[1] == ":":
            cleaned = cleaned[2:].lstrip("/")

        # Check for traversal tokens
        parts = cleaned.split("/")
        safe_parts = []
        for p in parts:
            if not p or p == ".":
                continue
            if p == "..":
                # Path traversal attempt
                return None
            safe_parts.append(p)

        return "/".join(safe_parts) if safe_parts else None

    @staticmethod
    def _is_within_root(path: str, root: str) -> bool:
        """Verify that resolved canonical path resides inside root."""
        norm_path = os.path.abspath(os.path.realpath(path))
        norm_root = os.path.abspath(os.path.realpath(root))
        try:
            return os.path.commonpath([norm_path, norm_root]) == norm_root
        except ValueError:
            return False
