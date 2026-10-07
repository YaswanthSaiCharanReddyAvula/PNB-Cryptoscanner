import asyncio
import uuid
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from app.scanner.cloud.models import (
    CloudCryptoAsset,
    CloudEvidence,
    CloudFinding,
    CloudPermissionState,
    CloudResource,
    CloudSecretObservation,
    CloudAuditTarget,
    IdentityContext,
)
from app.scanner.cloud.provider_adapter import CloudProviderAdapter
from app.utils.logger import get_logger

logger = get_logger(__name__)


class AWSCloudAdapter(CloudProviderAdapter):
    """Adapter for auditing AWS resources without extracting secret material."""

    def __init__(self, target: CloudAuditTarget):
        self.target = target
        self.evidence: list[CloudEvidence] = []
        self.findings: list[CloudFinding] = []
        self._session = None
        self._identity = None

    def _record_evidence(
        self,
        account_id: str,
        region: str,
        resource_id: str,
        resource_type: str,
        observation_type: str,
        permission_status: CloudPermissionState = CloudPermissionState.SUCCESS,
    ):
        ev = CloudEvidence(
            evidence_id=f"ev-aws-{uuid.uuid4().hex[:8]}",
            provider="aws",
            account_id=account_id,
            region=region,
            resource_id=resource_id,
            resource_type=resource_type,
            observation_type=observation_type,
            collector="AWSCloudAdapter",
            permission_status=permission_status,
        )
        self.evidence.append(ev)

    async def authenticate(self) -> bool:
        if not BOTO3_AVAILABLE:
            logger.error("boto3 is not installed. Cannot authenticate with AWS.")
            return False

        try:
            # For simplicity, we use the default session or profile name if specified.
            # Real implementation would handle STS AssumeRole based on credential_reference.
            profile_name = None
            if self.target.credential_reference and self.target.credential_reference.credential_type == "profile":
                profile_name = self.target.credential_reference.reference_id

            self._session = boto3.Session(profile_name=profile_name)
            sts = self._session.client("sts")
            # This is synchronous in boto3, we should wrap it or use aioboto3. 
            # For this MVP, we use asyncio.to_thread
            caller = await asyncio.to_thread(sts.get_caller_identity)
            
            self._identity = IdentityContext(
                provider="aws",
                account_id=caller["Account"],
                principal=caller["Arn"],
                principal_type="iam",
                is_valid=True
            )
            return True
        except (ClientError, BotoCoreError) as e:
            logger.warning(f"AWS Authentication failed: {e}")
            self._identity = IdentityContext(
                provider="aws",
                account_id="unknown",
                principal="unknown",
                principal_type="unknown",
                is_valid=False
            )
            return False

    async def get_identity(self) -> IdentityContext:
        return self._identity

    async def discover_accounts(self) -> list[str]:
        # If Organizations is permitted, we could enumerate. For now, return self.
        if self._identity and self._identity.is_valid:
            # Respect explicit scope
            if self.target.scope.accounts:
                return self.target.scope.accounts
            return [self._identity.account_id]
        return []

    async def discover_regions(self, account_id: str) -> list[str]:
        if self.target.scope.regions:
            return self.target.scope.regions
        try:
            ec2 = self._session.client("ec2", region_name="us-east-1")
            resp = await asyncio.to_thread(ec2.describe_regions)
            return [r["RegionName"] for r in resp["Regions"]]
        except Exception:
            return ["us-east-1"]

    async def collect_iam(self, account_id: str, region: str) -> AsyncIterator[CloudResource]:
        if region != "us-east-1":
            return  # IAM is global, only scan once

        iam = self._session.client("iam", region_name="us-east-1")
        try:
            paginator = iam.get_paginator('list_users')
            # Using asyncio.to_thread for blocking generator - standard boto3 limitation
            for page in await asyncio.to_thread(lambda: list(paginator.paginate())):
                for user in page['Users']:
                    res = CloudResource(
                        provider="aws",
                        resource_id=user["Arn"],
                        resource_type="iam_user",
                        account_id=account_id,
                        region="global",
                    )
                    self._record_evidence(account_id, "global", res.resource_id, "iam_user", "discovered")
                    yield res
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                self._record_evidence(account_id, "global", "iam:*", "iam", "access_denied", CloudPermissionState.PERMISSION_DENIED)
            else:
                self._record_evidence(account_id, "global", "iam:*", "iam", "service_error", CloudPermissionState.SERVICE_ERROR)

    async def collect_keys(self, account_id: str, region: str) -> AsyncIterator[CloudCryptoAsset]:
        kms = self._session.client("kms", region_name=region)
        try:
            paginator = kms.get_paginator('list_keys')
            for page in await asyncio.to_thread(lambda: list(paginator.paginate())):
                for key in page['Keys']:
                    key_id = key["KeyId"]
                    try:
                        # Get metadata only
                        metadata = await asyncio.to_thread(kms.describe_key, KeyId=key_id)
                        k = metadata["KeyMetadata"]
                        
                        asset = CloudCryptoAsset(
                            provider="aws",
                            resource_id=k["Arn"],
                            asset_type="kms_key",
                            algorithm=k.get("CustomerMasterKeySpec", "SYMMETRIC_DEFAULT"),
                            purpose=k.get("KeyUsage", "ENCRYPT_DECRYPT"),
                            creation_time=k.get("CreationDate"),
                            owner=k.get("KeyManager", "CUSTOMER"),
                            usage_state=k.get("KeyState", "UNKNOWN")
                        )
                        self._record_evidence(account_id, region, asset.resource_id, "kms_key", "discovered")
                        
                        # Check rotation if authorized
                        try:
                            rotation = await asyncio.to_thread(kms.get_key_rotation_status, KeyId=key_id)
                            asset.rotation_enabled = rotation.get("KeyRotationEnabled", False)
                        except ClientError:
                            pass
                            
                        yield asset
                    except ClientError:
                        self._record_evidence(account_id, region, key_id, "kms_key", "metadata_access_denied", CloudPermissionState.PERMISSION_DENIED)
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                self._record_evidence(account_id, region, "kms:*", "kms", "access_denied", CloudPermissionState.PERMISSION_DENIED)

    async def collect_secrets(self, account_id: str, region: str) -> AsyncIterator[CloudSecretObservation]:
        sm = self._session.client("secretsmanager", region_name=region)
        try:
            paginator = sm.get_paginator('list_secrets')
            for page in await asyncio.to_thread(lambda: list(paginator.paginate())):
                for secret in page['SecretList']:
                    obs = CloudSecretObservation(
                        provider="aws",
                        resource_id=secret["ARN"],
                        name=secret["Name"],
                        secret_type="secrets_manager",
                        creation_time=secret.get("CreatedDate"),
                        last_changed=secret.get("LastChangedDate"),
                        rotation_enabled=secret.get("RotationEnabled", False),
                        encryption_key=secret.get("KmsKeyId")
                    )
                    self._record_evidence(account_id, region, obs.resource_id, "secret", "discovered")
                    yield obs
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                self._record_evidence(account_id, region, "secretsmanager:*", "secretsmanager", "access_denied", CloudPermissionState.PERMISSION_DENIED)

    async def collect_certificates(self, account_id: str, region: str) -> AsyncIterator[CloudCryptoAsset]:
        acm = self._session.client("acm", region_name=region)
        try:
            paginator = acm.get_paginator('list_certificates')
            for page in await asyncio.to_thread(lambda: list(paginator.paginate())):
                for cert in page['CertificateSummaryList']:
                    cert_arn = cert["CertificateArn"]
                    try:
                        metadata = await asyncio.to_thread(acm.describe_certificate, CertificateArn=cert_arn)
                        c = metadata["Certificate"]
                        
                        asset = CloudCryptoAsset(
                            provider="aws",
                            resource_id=c["CertificateArn"],
                            asset_type="certificate",
                            algorithm=c.get("KeyAlgorithm", "UNKNOWN"),
                            purpose="TLS",
                            creation_time=c.get("CreatedAt"),
                            usage_state=c.get("Status", "UNKNOWN")
                        )
                        self._record_evidence(account_id, region, asset.resource_id, "certificate", "discovered")
                        yield asset
                    except ClientError:
                        pass
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                self._record_evidence(account_id, region, "acm:*", "acm", "access_denied", CloudPermissionState.PERMISSION_DENIED)

    async def collect_permissions(self, account_id: str, region: str) -> AsyncIterator[CloudFinding]:
        # Would implement Access Analyzer / IAM policy evaluation here.
        # Returning empty for MVP.
        return
        yield

    async def collect_findings(self) -> list[CloudFinding]:
        return self.findings

    def get_evidence(self) -> list[CloudEvidence]:
        return self.evidence
