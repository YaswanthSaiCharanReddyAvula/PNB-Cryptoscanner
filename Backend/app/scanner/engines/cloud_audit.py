"""
QuantumShield — Cloud Audit Engine (Stage 16)

Executes cloud provider adapters to discover, inspect, and analyze cloud cryptographic assets.
"""

from __future__ import annotations

import asyncio
from typing import Any

from app.scanner.cloud.models import CloudAuditTarget
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
    StageResult,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


class CloudAuditEngine(ScanStage):
    """Cloud Audit Engine."""

    name = "cloud_audit"
    order = 25  # Run after Track A and B, before CBOM unification
    timeout_seconds = 300
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields: list[str] = []
    writes_fields = [
        "cloud_crypto_assets",
        "cloud_secret_observations",
        "cloud_findings",
        "cloud_evidence",
    ]
    merge_strategy = MergeStrategy.APPEND

    def _instantiate_adapter(self, provider: str, target: CloudAuditTarget) -> Any:
        if provider == "aws":
            from app.scanner.cloud.providers.aws.adapter import AWSCloudAdapter
            return AWSCloudAdapter(target)
        elif provider == "azure":
            from app.scanner.cloud.providers.azure.adapter import AzureCloudAdapter
            return AzureCloudAdapter(target)
        elif provider == "gcp":
            from app.scanner.cloud.providers.gcp.adapter import GCPCloudAdapter
            return GCPCloudAdapter(target)
        elif provider == "kubernetes":
            from app.scanner.cloud.providers.kubernetes.adapter import KubernetesCloudAdapter
            return KubernetesCloudAdapter(target)
        return None

    async def execute(self, ctx: ScanContext) -> StageResult:
        targets_raw = ctx.options.get("cloud_targets", [])
        if not targets_raw:
            logger.info("[%s] Cloud Audit: No targets configured — skipping", ctx.scan_id)
            return StageResult(status="skipped", data={})

        assets = []
        secrets = []
        findings = []
        evidence = []

        for target_dict in targets_raw:
            try:
                target = CloudAuditTarget.model_validate(target_dict)
            except Exception as e:
                logger.error("Invalid cloud target configuration: %s", e)
                continue
                
            adapter = self._instantiate_adapter(target.provider, target)
            if not adapter:
                logger.warning("No adapter found for provider: %s", target.provider)
                continue
                
            logger.info("Authenticating with %s adapter...", target.provider)
            auth_success = await adapter.authenticate()
            if not auth_success:
                logger.warning("Authentication failed for %s", target.provider)
                # Still collect evidence of auth failure
                evidence.extend([e.model_dump() for e in adapter.get_evidence()])
                continue
                
            accounts = await adapter.discover_accounts()
            for account in accounts:
                regions = await adapter.discover_regions(account)
                for region in regions:
                    # IAM
                    async for _ in adapter.collect_iam(account, region):
                        pass
                        
                    # KMS Keys
                    async for key in adapter.collect_keys(account, region):
                        assets.append(key.model_dump())
                        
                    # Secrets (Metadata only)
                    async for secret in adapter.collect_secrets(account, region):
                        secrets.append(secret.model_dump())
                        
                    # Certificates
                    async for cert in adapter.collect_certificates(account, region):
                        assets.append(cert.model_dump())
                        
                    # Permissions
                    async for finding in adapter.collect_permissions(account, region):
                        findings.append(finding.model_dump())
                        
            # Collect aggregated findings and evidence
            findings.extend([f.model_dump() for f in await adapter.collect_findings()])
            evidence.extend([e.model_dump() for e in adapter.get_evidence()])

        # Also push cloud crypto assets to ctx.crypto_observations for CBOM merging
        crypto_obs = getattr(ctx, "crypto_observations", [])
        for a in assets:
            obs = {
                "artifact_type": a["asset_type"],
                "algorithm": a["algorithm"],
                "file_path": a["resource_id"],  # Use ARN/Resource ID as path for CBOM compat
                "key_size": a.get("key_size"),
                "fingerprint": a["resource_id"]
            }
            crypto_obs.append(obs)
            
        ctx.crypto_observations = crypto_obs

        return StageResult(
            status="completed",
            data={
                "cloud_crypto_assets": assets,
                "cloud_secret_observations": secrets,
                "cloud_findings": findings,
                "cloud_evidence": evidence,
            }
        )
