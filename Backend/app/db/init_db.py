"""
QuantumShield — Database Initialisation

Creates all PostgreSQL tables and seeds the default admin user.
Run once on startup via lifespan, or manually for dev resets.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from app.db.postgres import engine, AsyncSessionLocal, Base
from app.db import pg_models          # noqa: F401  — ensure models are imported before create_all
from app.core.security import hash_password

logger = logging.getLogger(__name__)

DEFAULT_ADMIN_EMAIL = "admin@quantumshield.com"
DEFAULT_ADMIN_PASSWORD = "admin123"


async def create_tables() -> None:
    """Create all tables (idempotent — skips existing tables)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("PostgreSQL tables created / verified.")


async def seed_admin() -> None:
    """Insert a default admin user if none exists."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(pg_models.User).where(pg_models.User.role == "admin")
        )
        existing_admin = result.scalars().first()
        if existing_admin:
            return

        admin = pg_models.User(
            email=DEFAULT_ADMIN_EMAIL,
            full_name="System Administrator",
            hashed_password=hash_password(DEFAULT_ADMIN_PASSWORD),
            role="admin",
        )
        session.add(admin)
        await session.commit()
        logger.info("Default admin user created: %s", DEFAULT_ADMIN_EMAIL)


async def seed_sample_data() -> None:
    """Seed realistic-looking sample rows so every GET endpoint returns data."""
    async with AsyncSessionLocal() as session:
        # Only seed if the tables are empty
        asset_count = (await session.execute(
            select(pg_models.Asset)
        )).scalars().first()
        if asset_count:
            return  # already seeded

        from datetime import datetime, timezone, timedelta

        now = datetime.now(timezone.utc)

        # Assets
        assets = [
            pg_models.Asset(asset_name="pnb-portal.pnb.co.in",  url="https://pnb-portal.pnb.co.in",  ipv4="203.88.130.1",   type="web_app", owner="IT Security", risk="high",     certificate_status="expiring_soon", key_length=2048, last_scan=now - timedelta(hours=2)),
            pg_models.Asset(asset_name="api.pnb.co.in",          url="https://api.pnb.co.in",          ipv4="203.88.130.2",   type="api",     owner="DevOps",      risk="medium",   certificate_status="valid",          key_length=4096, last_scan=now - timedelta(hours=5)),
            pg_models.Asset(asset_name="mail.pnb.co.in",          url="https://mail.pnb.co.in",          ipv4="203.88.130.3",   type="server",  owner="IT Ops",      risk="low",      certificate_status="valid",          key_length=2048, last_scan=now - timedelta(days=1)),
            pg_models.Asset(asset_name="netbanking.pnb.co.in",   url="https://netbanking.pnb.co.in",   ipv4="203.88.130.4",   type="web_app", owner="Digital",     risk="critical", certificate_status="valid",          key_length=1024, last_scan=now - timedelta(hours=1)),
            pg_models.Asset(asset_name="vpn.pnb.co.in",          url="https://vpn.pnb.co.in",          ipv4="203.88.130.5",   type="server",  owner="Network",     risk="medium",   certificate_status="expired",        key_length=2048, last_scan=now - timedelta(days=3)),
            pg_models.Asset(asset_name="cdn.pnb.co.in",          url="https://cdn.pnb.co.in",          ipv4="203.88.130.6",   type="web_app", owner="IT Security", risk="low",      certificate_status="valid",          key_length=4096, last_scan=now - timedelta(hours=8)),
            pg_models.Asset(asset_name="reporting.pnb.co.in",    url="https://reporting.pnb.co.in",    ipv4="203.88.130.7",   type="api",     owner="Analytics",   risk="medium",   certificate_status="valid",          key_length=2048, last_scan=now - timedelta(hours=12)),
            pg_models.Asset(asset_name="auth.pnb.co.in",         url="https://auth.pnb.co.in",         ipv4="203.88.130.8",   type="api",     owner="IAM Team",    risk="high",     certificate_status="expiring_soon",  key_length=2048, last_scan=now - timedelta(hours=3)),
        ]
        session.add_all(assets)

        # Name servers
        nameservers = [
            pg_models.NameServer(hostname="ns1.pnb.co.in",  type="A",     ip_address="203.88.130.10",  ttl=3600),
            pg_models.NameServer(hostname="ns2.pnb.co.in",  type="A",     ip_address="203.88.130.11",  ttl=3600),
            pg_models.NameServer(hostname="mail.pnb.co.in", type="MX",    ip_address="203.88.130.20",  ttl=1800),
            pg_models.NameServer(hostname="pnb.co.in",      type="TXT",   ip_address=None,             ttl=300),
            pg_models.NameServer(hostname="vpn.pnb.co.in",  type="CNAME", ip_address="203.88.130.5",   ttl=7200),
        ]
        session.add_all(nameservers)

        # Crypto records
        crypto = [
            pg_models.CryptoRecord(asset="netbanking.pnb.co.in",  key_length=1024, cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",        tls_version="TLS 1.0", certificate_authority="DigiCert Inc"),
            pg_models.CryptoRecord(asset="api.pnb.co.in",         key_length=4096, cipher_suite="TLS_AES_256_GCM_SHA384",              tls_version="TLS 1.3", certificate_authority="Let's Encrypt"),
            pg_models.CryptoRecord(asset="pnb-portal.pnb.co.in",  key_length=2048, cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", tls_version="TLS 1.2", certificate_authority="DigiCert Inc"),
            pg_models.CryptoRecord(asset="auth.pnb.co.in",        key_length=2048, cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", tls_version="TLS 1.2", certificate_authority="Sectigo"),
            pg_models.CryptoRecord(asset="vpn.pnb.co.in",         key_length=2048, cipher_suite="TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",  tls_version="TLS 1.1", certificate_authority="GlobalSign"),
        ]
        session.add_all(crypto)

        # Asset inventory
        inventory = [
            pg_models.AssetInventory(detection_date=now - timedelta(days=30), ip_address="203.88.130.1",  ports="443,80,8443",   subnets="203.88.130.0/24", asn="AS9821", net_name="PNB-IN", location="New Delhi, IN",    company="Punjab National Bank"),
            pg_models.AssetInventory(detection_date=now - timedelta(days=20), ip_address="203.88.130.2",  ports="443,8080",      subnets="203.88.130.0/24", asn="AS9821", net_name="PNB-IN", location="Mumbai, IN",        company="Punjab National Bank"),
            pg_models.AssetInventory(detection_date=now - timedelta(days=15), ip_address="203.88.130.5",  ports="1194,443",      subnets="203.88.130.0/24", asn="AS9821", net_name="PNB-IN", location="Bangalore, IN",     company="Punjab National Bank"),
            pg_models.AssetInventory(detection_date=now - timedelta(days=10), ip_address="203.88.130.8",  ports="443,8443,3000", subnets="203.88.130.0/24", asn="AS9821", net_name="PNB-IN", location="Hyderabad, IN",     company="Punjab National Bank"),
        ]
        session.add_all(inventory)

        # CBOM summary
        cbom_summary = pg_models.CBOMSummary(
            total_applications=240,
            sites_surveyed=45,
            active_certificates=198,
            weak_cryptography=32,
            certificate_issues=12,
        )
        session.add(cbom_summary)

        await session.commit()
        logger.info("Sample seed data inserted.")


async def init_db() -> None:
    await create_tables()
    await seed_admin()
    # await seed_sample_data()  # Disabled: User wants real scan data


if __name__ == "__main__":
    asyncio.run(init_db())
