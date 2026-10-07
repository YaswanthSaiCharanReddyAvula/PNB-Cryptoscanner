"""
QuantumShield — Cloud Provider Adapter Interface (Phase 1)

Defines the contract for all cloud provider adapters (AWS, Azure, GCP, K8s).
"""

from abc import ABC, abstractmethod
from typing import AsyncIterator

from app.scanner.cloud.models import (
    CloudCryptoAsset,
    CloudEvidence,
    CloudFinding,
    CloudResource,
    CloudSecretObservation,
    IdentityContext,
)


class CloudProviderAdapter(ABC):
    """Abstract base class for cloud provider adapters."""

    @abstractmethod
    async def authenticate(self) -> bool:
        """Establish session using the configured credential reference."""
        pass

    @abstractmethod
    async def get_identity(self) -> IdentityContext:
        """Validate credentials and return the principal identity."""
        pass

    @abstractmethod
    async def discover_accounts(self) -> list[str]:
        """Enumerate accounts/subscriptions if authorized and in scope."""
        pass

    @abstractmethod
    async def discover_regions(self, account_id: str) -> list[str]:
        """Enumerate regions to scan."""
        pass

    @abstractmethod
    async def collect_iam(self, account_id: str, region: str) -> AsyncIterator[CloudResource]:
        """Collect IAM metadata."""
        pass
        
    # The abstract methods require yield type hinting for async generator or return list
    # Using AsyncIterator for pagination support.
    
    @abstractmethod
    async def collect_keys(self, account_id: str, region: str) -> AsyncIterator[CloudCryptoAsset]:
        """Collect KMS/Key Vault keys."""
        pass

    @abstractmethod
    async def collect_secrets(self, account_id: str, region: str) -> AsyncIterator[CloudSecretObservation]:
        """Collect secrets metadata. Must NEVER return secret values."""
        pass

    @abstractmethod
    async def collect_certificates(self, account_id: str, region: str) -> AsyncIterator[CloudCryptoAsset]:
        """Collect cloud-managed certificates."""
        pass

    @abstractmethod
    async def collect_permissions(self, account_id: str, region: str) -> AsyncIterator[CloudFinding]:
        """Analyze permissions and trust policies."""
        pass

    @abstractmethod
    async def collect_findings(self) -> list[CloudFinding]:
        """Return any aggregated findings generated during collection."""
        pass

    @abstractmethod
    def get_evidence(self) -> list[CloudEvidence]:
        """Return evidence objects documenting permission states and errors."""
        pass
