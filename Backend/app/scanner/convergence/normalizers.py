"""
QuantumShield — Convergence Normalizers

Normalizes input data (IPs, URLs, hostnames, versions, technologies)
into their canonical forms.
"""

import ipaddress
import re
from typing import Dict, Optional, Tuple, Union
from urllib.parse import urlparse, urlunparse


def normalize_hostname(raw_hostname: str) -> str:
    """
    Normalizes a hostname to its canonical form (lowercase, stripped, no trailing dot, no URL parts).
    Example: 'https://Example.COM:443/' -> 'example.com'
             'Example.COM.' -> 'example.com'
    """
    if not raw_hostname:
        return ""
    
    val = raw_hostname.strip()
    if val.startswith(("http://", "https://")):
        parsed = urlparse(val)
        val = parsed.hostname or val
    
    # Strip port if present (e.g., example.com:443)
    if ":" in val:
        # Check if it's an IPv6 address, avoid stripping if it is
        try:
            ipaddress.IPv6Address(val.strip("[]"))
        except ValueError:
            val = val.split(":")[0]

    val = val.lower().strip()
    if val.endswith("."):
        val = val[:-1]
    
    return val


def normalize_ip(raw_ip: str) -> Optional[str]:
    """
    Normalizes IPv4 and IPv6 addresses.
    Returns the canonical string representation of the IP, or None if invalid.
    """
    try:
        ip = ipaddress.ip_address(raw_ip.strip("[] \t\n\r"))
        return str(ip)
    except ValueError:
        return None


def normalize_url(raw_url: str) -> str:
    """
    Normalizes a URL to a consistent scheme://hostname[:port]/path?query#fragment format.
    """
    try:
        parsed = urlparse(raw_url.strip())
        # Rebuild URL to ensure consistent casing for scheme and netloc
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        return urlunparse((scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    except Exception:
        return raw_url.strip()


def normalize_port(port: int, transport: str = "tcp") -> Dict[str, Union[int, str]]:
    """
    Creates a canonical representation of a port and transport protocol.
    """
    return {
        "port": int(port),
        "transport": transport.lower()
    }


def normalize_technology(raw_name: str) -> str:
    """
    Normalizes a technology name case-insensitively.
    """
    return raw_name.strip().lower()


def normalize_version(raw_version: str) -> Dict[str, str]:
    """
    Preserves raw version and provides a normalized comparison form.
    E.g., 'v1.24.0-rc1' -> raw: 'v1.24.0-rc1', normalized: '1.24.0'
    """
    raw = raw_version.strip()
    
    # Basic normalization: strip 'v' prefix and try to extract the semver core
    normalized = raw
    if normalized.lower().startswith("v"):
        normalized = normalized[1:]
    
    # Extract just the numeric/dot parts for base comparison (naive approach, handles simple semver)
    match = re.match(r"^(\d+\.\d+(?:\.\d+)?).*", normalized)
    if match:
        normalized = match.group(1)
        
    return {
        "raw_version": raw,
        "normalized_version": normalized
    }


def normalize_elliptic_curve(curve_name: str) -> str:
    """
    Normalizes known elliptic curve aliases to a canonical identity.
    """
    name = curve_name.strip().lower()
    
    # secp256r1 aliases
    if name in ["prime256v1", "secp256r1", "p-256", "nist p-256"]:
        return "secp256r1"
    
    # secp384r1 aliases
    if name in ["secp384r1", "p-384", "nist p-384"]:
        return "secp384r1"
        
    # secp521r1 aliases
    if name in ["secp521r1", "p-521", "nist p-521"]:
        return "secp521r1"
        
    return curve_name.strip()


class NormalizationEngine:
    """
    Centralized service for canonical normalization as defined by the Phase 3 Architecture.
    Delegates to specific normalization functions.
    """
    
    @classmethod
    def normalize_hostname(cls, raw: str) -> str:
        return normalize_hostname(raw)
        
    @classmethod
    def normalize_ip(cls, raw: str) -> Optional[str]:
        return normalize_ip(raw)
        
    @classmethod
    def normalize_url(cls, raw: str) -> str:
        return normalize_url(raw)
        
    @classmethod
    def normalize_port(cls, port: int, transport: str = "tcp") -> Dict[str, Union[int, str]]:
        return normalize_port(port, transport)
        
    @classmethod
    def normalize_technology(cls, raw: str) -> str:
        return normalize_technology(raw)
        
    @classmethod
    def normalize_version(cls, raw: str) -> Dict[str, str]:
        return normalize_version(raw)
        
    @classmethod
    def normalize_elliptic_curve(cls, raw: str) -> str:
        return normalize_elliptic_curve(raw)

