"""
QuantumShield — Source Acquisition Models
"""

from typing import Optional
from pydantic import BaseModel


class ScanSource(BaseModel):
    """Normalized source target for SAST."""
    source_type: str  # local, github_repo, github_branch, github_folder, github_file
    original_url: str
    provider: str  # github, local
    repository_owner: Optional[str] = None
    repository_name: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    selected_scope: str  # e.g., "/" or "src/crypto"
    local_root: str  # The absolute path to the local root of the acquired source
    acquisition_timestamp: Optional[str] = None

    @property
    def repository(self) -> str:
        if self.repository_owner and self.repository_name:
            return f"{self.repository_owner}/{self.repository_name}"
        return "local"
