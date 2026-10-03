"""
QuantumShield — Recursive Source Discovery
"""

import os
from pydantic import BaseModel
from typing import List

from app.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_EXCLUSIONS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "target", "coverage", ".cache", ".idea", ".vscode",
    "vendor", "site-packages"
})

# Supported languages and their extensions
LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "java": {".java", ".kt", ".scala"},
    "javascript": {".js", ".jsx", ".cjs", ".mjs"},
    "typescript": {".ts", ".tsx"},
    "go": {".go"},
}

# Reverse mapping: extension -> language
EXT_TO_LANG = {ext: lang for lang, exts in LANGUAGE_EXTENSIONS.items() for ext in exts}


class SourceFile(BaseModel):
    file_path: str
    relative_path: str
    language: str
    extension: str
    size: int


class DiscoveryMetrics(BaseModel):
    files_discovered: int = 0
    files_analyzed: int = 0
    files_skipped: int = 0
    parser_errors: int = 0


class SourceDiscoveryError(Exception):
    pass


class SourceDiscoveryManager:
    def __init__(
        self,
        max_file_size: int = 2 * 1024 * 1024, # 2MB
        max_directory_depth: int = 50,
        exclusions: frozenset[str] = DEFAULT_EXCLUSIONS,
    ):
        self.max_file_size = max_file_size
        self.max_directory_depth = max_directory_depth
        self.exclusions = exclusions

    def discover(self, local_scan_root: str, selected_scope: str = "/") -> tuple[List[SourceFile], List[dict]]:
        """
        Recursively discover supported source files in the local path, restricted by scope.
        Returns (discovered_files, skipped_files_evidence).
        """
        abs_root = os.path.abspath(local_scan_root)
        
        # Determine actual search directory based on scope
        scope_path = selected_scope.lstrip("/")
        search_root = os.path.abspath(os.path.join(abs_root, scope_path))
        
        # Prevent directory traversal escape
        if not search_root.startswith(abs_root):
            raise SourceDiscoveryError("Scope traversal escape detected")

        if not os.path.exists(search_root):
            # It's possible the scope points to a single file
            if os.path.isfile(search_root):
                return self._process_single_file(search_root, abs_root)
            return [], []

        source_files = []
        skipped_files = []

        for root, dirs, files in os.walk(search_root, topdown=True, followlinks=False):
            # Depth check
            rel_root = os.path.relpath(root, search_root)
            if rel_root == ".":
                depth = 0
            else:
                depth = len(rel_root.split(os.sep))
                
            if depth >= self.max_directory_depth:
                dirs[:] = [] # Stop recursion here
                continue

            # Apply exclusions to directories
            # Only exclude if they aren't part of the selected scope path itself
            dirs[:] = [d for d in dirs if d not in self.exclusions]

            for filename in files:
                file_path = os.path.join(root, filename)
                
                # Check extension
                _, ext = os.path.splitext(filename)
                ext = ext.lower()
                
                lang = EXT_TO_LANG.get(ext)
                if not lang:
                    continue # Ignore unsupported extensions silently for now

                # Avoid symlinks
                if os.path.islink(file_path):
                    continue
                
                # Check size
                try:
                    size = os.path.getsize(file_path)
                except OSError:
                    continue
                
                relative_path = os.path.relpath(file_path, abs_root)

                if size > self.max_file_size:
                    skipped_files.append({
                        "file_path": relative_path,
                        "reason": "SKIPPED_FILE_TOO_LARGE",
                        "size": size,
                    })
                    continue

                source_files.append(SourceFile(
                    file_path=file_path,
                    relative_path=relative_path,
                    language=lang,
                    extension=ext,
                    size=size,
                ))

        return source_files, skipped_files

    def _process_single_file(self, file_path: str, abs_root: str) -> tuple[List[SourceFile], List[dict]]:
        if os.path.islink(file_path):
            return [], []
            
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        lang = EXT_TO_LANG.get(ext)
        if not lang:
            return [], []

        try:
            size = os.path.getsize(file_path)
        except OSError:
            return [], []

        relative_path = os.path.relpath(file_path, abs_root)

        if size > self.max_file_size:
            return [], [{
                "file_path": relative_path,
                "reason": "SKIPPED_FILE_TOO_LARGE",
                "size": size,
            }]

        return [SourceFile(
            file_path=file_path,
            relative_path=relative_path,
            language=lang,
            extension=ext,
            size=size,
        )], []
