import logging
from datetime import datetime, timezone
from sqlalchemy import select
from app.db.postgres import AsyncSessionLocal
from app.db import pg_models
from app.db.models import CryptoComponent, QuantumScore

logger = logging.getLogger(__name__)

async def sync_scan_to_postgres(domain: str, assets_discovered: list, tls_results: list, cbom_components: list, quantum_score: dict) -> None:
    """
    Synchronizes the scan results from the MongoDB pipeline into the PostgreSQL database 
    so the v2 endpoints can serve actual scan data.
    """
    logger.info("Syncing scan results for %s to PostgreSQL...", domain)
    async with AsyncSessionLocal() as session:
        now = datetime.now(timezone.utc)
        
        # 1. Assets sync
        for asset in assets_discovered:
            # Upsert asset
            result = await session.execute(
                select(pg_models.Asset).where(pg_models.Asset.url == f"https://{asset.subdomain}")
            )
            existing_asset = result.scalars().first()
            if not existing_asset:
                existing_asset = pg_models.Asset(
                    asset_name=asset.subdomain,
                    url=f"https://{asset.subdomain}",
                    type="domain",
                    owner="Unknown",
                    risk="low",
                    created_at=now
                )
                session.add(existing_asset)
            existing_asset.ipv4 = asset.ip
            existing_asset.last_scan = now
            # Find matching tls result for cert status and key length
            for tls in tls_results:
                if tls.host == asset.subdomain and tls.cert_chain:
                    cert = tls.cert_chain[0]
                    existing_asset.certificate_status = "valid"  # Simplified
                    existing_asset.key_length = cert.public_key_size
                    break

        # 2. Crypto Records sync
        for comp in cbom_components:
            # Ensure an asset entity exists for this component's URL
            result = await session.execute(
                select(pg_models.Asset).where(pg_models.Asset.url == f"https://{domain}")
            )
            existing_asset = result.scalars().first()
            if not existing_asset:
                existing_asset = pg_models.Asset(
                    asset_name=domain,
                    url=f"https://{domain}",
                    type="domain",
                    owner="Unknown",
                    risk="low",
                    last_scan=now,
                    created_at=now
                )
                session.add(existing_asset)

            # Insert Crypto Record
            record = pg_models.CryptoRecord(
                asset=domain,
                key_length=comp.key_size,
                cipher_suite=comp.name,
                tls_version="Unknown", # Simplified
                certificate_authority="Unknown", # Simplified
                created_at=now
            )
            session.add(record)

        # 3. CBOM Summary Update (Overall aggregator)
        result = await session.execute(select(pg_models.CBOMSummary))
        summary = result.scalars().first()
        if not summary:
            summary = pg_models.CBOMSummary()
            session.add(summary)
            
        summary.total_applications = (summary.total_applications or 0) + len(assets_discovered)
        summary.sites_surveyed = (summary.sites_surveyed or 0) + 1
        summary.active_certificates = (summary.active_certificates or 0) + len(tls_results)
        # simplistic count for weak crypto
        weak_count = sum(1 for c in cbom_components if c.risk_level in ["High", "Critical"])
        summary.weak_cryptography = (summary.weak_cryptography or 0) + weak_count

        await session.commit()
        logger.info("Successfully synced real scan data for %s to PostgreSQL.", domain)
