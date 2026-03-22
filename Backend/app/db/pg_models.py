"""
QuantumShield — PostgreSQL ORM Models

All SQLAlchemy table definitions for the Assessment System.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer, String, Text, ForeignKey, ARRAY
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.postgres import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Users ────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="employee")  # admin | employee
    is_active = Column(Boolean, default=True)
    reset_token = Column(String(255), nullable=True)
    reset_token_expires = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now)

    reports = relationship("Report", back_populates="creator", lazy="selectin")


# ── Assets ───────────────────────────────────────────────────────

class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_name = Column(String(255), nullable=False)
    url = Column(String(512), nullable=True)
    ipv4 = Column(String(45), nullable=True)
    ipv6 = Column(String(45), nullable=True)
    type = Column(String(100), nullable=True)     # web_app | api | server | etc.
    owner = Column(String(255), nullable=True)
    risk = Column(String(50), default="low")      # critical | high | medium | low | safe
    certificate_status = Column(String(100), nullable=True)
    key_length = Column(Integer, nullable=True)
    last_scan = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now)


# ── Name Server Records ──────────────────────────────────────────

class NameServer(Base):
    __tablename__ = "nameservers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String(512), nullable=False)
    type = Column(String(50), nullable=False)   # A | AAAA | CNAME | MX | NS | TXT
    ip_address = Column(String(45), nullable=True)
    ttl = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now)


# ── Crypto Security Records ──────────────────────────────────────

class CryptoRecord(Base):
    __tablename__ = "crypto_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset = Column(String(255), nullable=False)
    key_length = Column(Integer, nullable=True)
    cipher_suite = Column(String(255), nullable=True)
    tls_version = Column(String(50), nullable=True)
    certificate_authority = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now)


# ── Asset Inventory ──────────────────────────────────────────────

class AssetInventory(Base):
    __tablename__ = "asset_inventory"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    detection_date = Column(DateTime(timezone=True), nullable=True)
    ip_address = Column(String(45), nullable=True)
    ports = Column(String(512), nullable=True)   # stored as comma-separated string
    subnets = Column(String(255), nullable=True)
    asn = Column(String(100), nullable=True)
    net_name = Column(String(255), nullable=True)
    location = Column(String(255), nullable=True)
    company = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now)


# ── CBOM Summary ─────────────────────────────────────────────────

class CBOMSummary(Base):
    __tablename__ = "cbom_summary"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    total_applications = Column(Integer, default=0)
    sites_surveyed = Column(Integer, default=0)
    active_certificates = Column(Integer, default=0)
    weak_cryptography = Column(Integer, default=0)
    certificate_issues = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=_now)


# ── Reports ──────────────────────────────────────────────────────

class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type = Column(String(100), nullable=False)   # executive | scheduled | on-demand
    format = Column(String(20), nullable=False)  # json | xml | csv | pdf
    content = Column(Text, nullable=True)        # serialised payload or file path
    scheduled_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    creator = relationship("User", back_populates="reports")
