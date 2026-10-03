"""
QuantumShield — Source Acquisition: GitHub and Local Intake
"""

import asyncio
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.scanner.acquisition.models import ScanSource
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Pattern for GitHub URLs
# e.g., https://github.com/company/repo
# e.g., https://github.com/company/repo/tree/main
# e.g., https://github.com/company/repo/tree/main/src/crypto
# e.g., https://github.com/company/repo/blob/main/src/crypto/aes.py
GITHUB_URL_PATTERN = re.compile(
    r"^https?://github\.com/([^/]+)/([^/]+)(?:/(tree|blob)/([^/]+)(?:/(.*))?)?$"
)


async def _run_git_command(args: list[str], cwd: str | None = None) -> tuple[int, str, str]:
    """Safely execute a Git command with timeouts and argument arrays."""
    process = await asyncio.create_subprocess_exec(
        "git", *args,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=300.0)
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        raise TimeoutError(f"Git command timed out: git {' '.join(args)}")

    return (
        process.returncode or 0,
        stdout_bytes.decode(errors="ignore").strip(),
        stderr_bytes.decode(errors="ignore").strip()
    )


class SourceAcquisitionError(Exception):
    pass


class SourceAcquisitionManager:
    """Manages secure intake of source repositories into isolated temporary workspaces."""

    def __init__(self, workspace_root: str = "/tmp/ecdat-sast"):
        self.workspace_root = workspace_root
        if not os.path.exists(self.workspace_root):
            os.makedirs(self.workspace_root, exist_ok=True)

    def parse_github_url(self, url: str) -> dict:
        """Parse a GitHub URL into its components."""
        parsed = urlparse(url)
        if parsed.netloc != "github.com":
            raise SourceAcquisitionError("Only GitHub URLs are currently supported")

        match = GITHUB_URL_PATTERN.match(url)
        if not match:
            raise SourceAcquisitionError(f"Malformed GitHub URL: {url}")

        owner = match.group(1)
        repo_name = match.group(2)
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        view_type = match.group(3)  # tree, blob, or None
        branch = match.group(4)
        scope = match.group(5) or ""

        source_type = "github_repo"
        if view_type == "tree" and scope:
            source_type = "github_folder"
        elif view_type == "tree" and not scope:
            source_type = "github_branch"
        elif view_type == "blob":
            source_type = "github_file"
        
        return {
            "source_type": source_type,
            "provider": "github",
            "repository_owner": owner,
            "repository_name": repo_name,
            "branch": branch,
            "selected_scope": "/" + scope if scope else "/",
        }

    async def acquire(self, scan_id: str, local_path: str = "", github_url: str = "") -> ScanSource:
        """Acquire source from local path or GitHub URL."""
        if local_path:
            return self._acquire_local(local_path)
        
        if github_url:
            return await self._acquire_github(scan_id, github_url)
            
        raise SourceAcquisitionError("Must provide either local_path or github_url")

    def _acquire_local(self, local_path: str) -> ScanSource:
        """Acquire a local directory for scanning (no-op copy/isolation for now if local)."""
        abs_path = os.path.abspath(local_path)
        if not os.path.exists(abs_path):
            raise SourceAcquisitionError(f"Local path does not exist: {abs_path}")
        
        return ScanSource(
            source_type="local",
            original_url=f"file://{abs_path}",
            provider="local",
            selected_scope="/",
            local_root=abs_path,
            acquisition_timestamp=datetime.now(timezone.utc).isoformat(),
        )

    async def _acquire_github(self, scan_id: str, url: str) -> ScanSource:
        """Clone a GitHub repository safely."""
        info = self.parse_github_url(url)
        
        scan_workspace = os.path.join(self.workspace_root, f"scan-{scan_id}", "repository")
        os.makedirs(scan_workspace, exist_ok=True)
        
        repo_url = f"https://github.com/{info['repository_owner']}/{info['repository_name']}.git"
        
        args = ["clone", "--depth", "1"]
        if info.get("branch"):
            args.extend(["--branch", info["branch"]])
        args.extend([repo_url, scan_workspace])

        logger.info("[%s] Cloning %s into %s", scan_id, repo_url, scan_workspace)
        code, stdout, stderr = await _run_git_command(args)
        if code != 0:
            raise SourceAcquisitionError(f"Failed to clone repository: {stderr}")

        # Get commit SHA
        code, stdout, stderr = await _run_git_command(["rev-parse", "HEAD"], cwd=scan_workspace)
        commit_sha = stdout if code == 0 else "unknown"

        # If no branch was specified, figure out what we got
        branch = info.get("branch")
        if not branch:
            code, stdout, stderr = await _run_git_command(["rev-parse", "--abbrev-ref", "HEAD"], cwd=scan_workspace)
            branch = stdout if code == 0 else "unknown"
            
        return ScanSource(
            source_type=info["source_type"],
            original_url=url,
            provider=info["provider"],
            repository_owner=info["repository_owner"],
            repository_name=info["repository_name"],
            branch=branch,
            commit_sha=commit_sha,
            selected_scope=info["selected_scope"],
            local_root=scan_workspace,
            acquisition_timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def cleanup(self, scan_id: str):
        """Clean up the temporary workspace for a scan."""
        scan_dir = os.path.join(self.workspace_root, f"scan-{scan_id}")
        if os.path.exists(scan_dir):
            try:
                shutil.rmtree(scan_dir)
                logger.info("[%s] Cleaned up workspace %s", scan_id, scan_dir)
            except OSError as e:
                logger.warning("[%s] Failed to clean up workspace: %s", scan_id, e)
