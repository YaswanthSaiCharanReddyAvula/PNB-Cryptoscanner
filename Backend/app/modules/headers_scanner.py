"""
QuantumShield — HTTP Security Headers Scanner

Checks for the presence and correctness of HTTP security headers
that protect against common web attacks and enforce TLS.
"""

import asyncio
import functools
import ssl
from typing import List
from urllib.request import urlopen, Request
from urllib.error import URLError

from app.db.models import HeaderFinding, HeadersResult, RiskLevel
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Headers to check and their security implications ─────────────

HEADER_CHECKS = [
    {
        "header": "Strict-Transport-Security",
        "risk_if_missing": RiskLevel.HIGH,
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce HTTPS.",
        "description": "HSTS prevents protocol downgrade attacks and cookie hijacking.",
    },
    {
        "header": "Content-Security-Policy",
        "risk_if_missing": RiskLevel.MEDIUM,
        "recommendation": "Add a Content-Security-Policy to prevent XSS and injection attacks.",
        "description": "CSP restricts resource loading origins to mitigate XSS.",
    },
    {
        "header": "X-Content-Type-Options",
        "risk_if_missing": RiskLevel.MEDIUM,
        "recommendation": "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
        "description": "Prevents browsers from interpreting files as a different MIME type.",
    },
    {
        "header": "X-Frame-Options",
        "risk_if_missing": RiskLevel.MEDIUM,
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
        "description": "Prevents the page from being loaded in iframes (clickjacking defense).",
    },
    {
        "header": "X-XSS-Protection",
        "risk_if_missing": RiskLevel.LOW,
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block' (legacy XSS filter).",
        "description": "Legacy header for XSS protection in older browsers.",
    },
    {
        "header": "Referrer-Policy",
        "risk_if_missing": RiskLevel.LOW,
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to control referrer data.",
        "description": "Controls how much referrer information is sent with requests.",
    },
    {
        "header": "Permissions-Policy",
        "risk_if_missing": RiskLevel.LOW,
        "recommendation": "Add 'Permissions-Policy' to restrict browser feature access (camera, mic, etc.).",
        "description": "Restricts which browser features the page can use.",
    },
    {
        "header": "X-Permitted-Cross-Domain-Policies",
        "risk_if_missing": RiskLevel.LOW,
        "recommendation": "Add 'X-Permitted-Cross-Domain-Policies: none' to restrict Flash/PDF cross-domain access.",
        "description": "Prevents Flash and Acrobat from loading cross-domain data.",
    },
    {
        "header": "Cache-Control",
        "risk_if_missing": RiskLevel.LOW,
        "recommendation": "Set 'Cache-Control: no-store' on sensitive pages to prevent caching.",
        "description": "Controls browser caching behavior for sensitive data.",
    },
    {
        "header": "Cross-Origin-Opener-Policy",
        "risk_if_missing": RiskLevel.LOW,
        "recommendation": "Add 'Cross-Origin-Opener-Policy: same-origin' to isolate browsing context.",
        "description": "Isolates the page from cross-origin popup attacks.",
    },
    {
        "header": "Cross-Origin-Resource-Policy",
        "risk_if_missing": RiskLevel.LOW,
        "recommendation": "Add 'Cross-Origin-Resource-Policy: same-origin' to restrict resource loading.",
        "description": "Prevents other origins from loading your resources.",
    },
]

# ── Headers that should NOT be present (information leakage) ─────

FORBIDDEN_HEADERS = [
    {
        "header": "Server",
        "risk_if_present": RiskLevel.LOW,
        "recommendation": "Remove or anonymize the 'Server' header to prevent version fingerprinting.",
    },
    {
        "header": "X-Powered-By",
        "risk_if_present": RiskLevel.MEDIUM,
        "recommendation": "Remove the 'X-Powered-By' header to hide framework/technology details.",
    },
    {
        "header": "X-AspNet-Version",
        "risk_if_present": RiskLevel.MEDIUM,
        "recommendation": "Remove 'X-AspNet-Version' to hide technology stack details.",
    },
]


def _scan_headers(host: str) -> HeadersResult:
    """Synchronous HTTP headers scan."""
    findings: List[HeaderFinding] = []
    url = f"https://{host}"

    try:
        # Create SSL context that doesn't verify (same approach as TLS scanner)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = Request(url, method="HEAD")
        req.add_header("User-Agent", "QuantumShield/1.0 Security Scanner")

        with urlopen(req, timeout=15, context=ctx) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Check required headers
            for check in HEADER_CHECKS:
                header_lower = check["header"].lower()
                present = header_lower in headers
                findings.append(HeaderFinding(
                    header=check["header"],
                    present=present,
                    value=headers.get(header_lower) if present else None,
                    risk_level=RiskLevel.SAFE if present else check["risk_if_missing"],
                    recommendation="" if present else check["recommendation"],
                ))

            # Check forbidden headers (info leakage)
            for check in FORBIDDEN_HEADERS:
                header_lower = check["header"].lower()
                present = header_lower in headers
                if present:
                    findings.append(HeaderFinding(
                        header=check["header"],
                        present=True,
                        value=headers.get(header_lower),
                        risk_level=check["risk_if_present"],
                        recommendation=check["recommendation"],
                    ))

    except URLError as e:
        logger.warning("HTTP headers scan failed for %s: %s", host, e)
        findings.append(HeaderFinding(
            header="CONNECTION",
            present=False,
            risk_level=RiskLevel.HIGH,
            recommendation=f"Headers scan failed: {e}",
        ))
    except Exception as e:
        logger.error("Unexpected error scanning headers for %s: %s", host, e)

    # Calculate score (0-100)
    required_count = len(HEADER_CHECKS)
    present_count = sum(1 for f in findings if f.present and f.risk_level == RiskLevel.SAFE)
    info_leak_count = sum(1 for f in findings if f.header in [h["header"] for h in FORBIDDEN_HEADERS] and f.present)
    score = max(0, (present_count / required_count * 100) - (info_leak_count * 5))

    logger.info("Headers scan for %s: %d/%d present, score=%.0f", host, present_count, required_count, score)

    return HeadersResult(
        host=host,
        findings=findings,
        score=round(score, 1),
    )


async def scan_headers(host: str) -> HeadersResult:
    """Async wrapper for HTTP headers scan."""
    logger.info("Scanning HTTP security headers on %s ...", host)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, functools.partial(_scan_headers, host)
    )
