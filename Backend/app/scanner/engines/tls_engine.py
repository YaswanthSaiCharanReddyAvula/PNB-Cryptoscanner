"""
QuantumShield — TLS/Crypto Engine (Stage 4)

Pure-Python TLS probing and certificate analysis using only the ssl stdlib
module and the cryptography library.  Replaces sslscan / testssl / zgrab2 /
openssl subprocess calls.
"""

from __future__ import annotations

import asyncio
import json
import ssl
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.scanner.models import (
    CertificateDetail,
    CipherDetail,
    StageResult,
    TLSProfile,
)
from app.scanner.pipeline import MergeStrategy, ScanContext, ScanStage, StageCriticality
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Static data directory ────────────────────────────────────────────────
_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# TLS version constants — graceful on builds that removed legacy versions
_TLS_VERSIONS: dict[str, ssl.TLSVersion | None] = {
    "TLSv1": getattr(ssl.TLSVersion, "TLSv1", None),
    "TLSv1_1": getattr(ssl.TLSVersion, "TLSv1_1", None),
    "TLSv1_2": getattr(ssl.TLSVersion, "TLSv1_2", None),
    "TLSv1_3": getattr(ssl.TLSVersion, "TLSv1_3", None),
}

_PQC_INDICATORS = ("kyber", "mlkem", "x25519kyber", "secp256r1mlkem")
_PROBE_TIMEOUT = 10  # per-connection timeout (seconds)

# Maps ssl_object.version() strings to our dict keys
_VER_DOTTED_TO_KEY: dict[str, str] = {
    "TLSv1.3": "TLSv1_3",
    "TLSv1.2": "TLSv1_2",
    "TLSv1.1": "TLSv1_1",
    "TLSv1": "TLSv1",
}


def _build_cipher_detail(name: str, info: dict[str, Any]) -> CipherDetail:
    return CipherDetail(
        name=name,
        kex=info.get("kex"),
        auth=info.get("auth"),
        encryption=info.get("encryption"),
        mac=info.get("mac"),
        bits=info.get("bits"),
        pfs=info.get("pfs", False),
        pqc=info.get("pqc", False),
        strength=info.get("strength", "unknown"),
    )


class TLSCryptoEngine(ScanStage):
    """Stage 4 — TLS handshake probing and certificate analysis."""

    name = "tls_engine"
    order = 4
    timeout_seconds = 90
    criticality = StageCriticality.IMPORTANT
    required_fields: list[str] = []  # runs even without services — fallback to subdomains:443
    writes_fields = ["tls_profiles"]
    merge_strategy = MergeStrategy.OVERWRITE

    _cipher_cache: dict[str, dict] | None = None
    _TLS_PORTS = frozenset({443, 8443, 465, 993, 995})
    _STARTTLS_PORTS = frozenset({25, 587, 143, 110})

    # ── throttle helper ──────────────────────────────────────────────

    @staticmethod
    @asynccontextmanager
    async def _throttled(
        ctx: ScanContext, category: str = "tls_probe",
    ) -> AsyncIterator[None]:
        if ctx.throttle:
            async with ctx.throttle.acquire(category):
                yield
        else:
            yield

    # ── cipher registry (lazy, cached at class level) ────────────────

    @classmethod
    def _load_cipher_registry(cls) -> dict[str, dict]:
        if cls._cipher_cache is None:
            path = _DATA_DIR / "cipher_registry.json"
            try:
                cls._cipher_cache = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("cipher_registry.json unavailable — empty cipher set")
                cls._cipher_cache = {}
        return cls._cipher_cache

    # ── 1. probe single TLS version ──────────────────────────────────

    async def _probe_tls_version(
        self,
        host: str,
        port: int,
        version: ssl.TLSVersion,
        ctx: ScanContext,
    ) -> bool:
        try:
            sc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            sc.check_hostname = False
            sc.verify_mode = ssl.CERT_NONE
            sc.minimum_version = version
            sc.maximum_version = version
        except (ValueError, AttributeError):
            return False

        try:
            async with self._throttled(ctx):
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host, port, ssl=sc, server_hostname=host,
                    ),
                    timeout=_PROBE_TIMEOUT,
                )
            writer.close()
            await writer.wait_closed()
            return True
        except (ssl.SSLError, TimeoutError, OSError, ConnectionError):
            return False

    # ── 2. probe all TLS versions ────────────────────────────────────

    async def _probe_all_versions(
        self, host: str, port: int, ctx: ScanContext,
    ) -> dict[str, bool]:
        out: dict[str, bool] = {}
        for label, ver in _TLS_VERSIONS.items():
            if ver is None:
                out[label] = False
            else:
                out[label] = await self._probe_tls_version(host, port, ver, ctx)
        return out

    # ── 3. enumerate accepted ciphers ────────────────────────────────

    async def _enumerate_ciphers(
        self, host: str, port: int, ctx: ScanContext,
    ) -> list[CipherDetail]:
        registry = self._load_cipher_registry()
        accepted: list[CipherDetail] = []

        tls13_std = [
            n for n in registry
            if n.startswith("TLS_")
            and "Kyber" not in n
            and "MLKEM" not in n
            and "mlkem" not in n
        ]
        tls13_pqc = [
            n for n in registry
            if n.startswith("TLS_")
            and ("Kyber" in n or "MLKEM" in n or "mlkem" in n)
        ]
        pre13 = [n for n in registry if not n.startswith("TLS_")]

        # TLS 1.3 standard ciphers — single probe (all standard suites
        # are available whenever TLS 1.3 negotiates successfully)
        if tls13_std:
            try:
                sc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                sc.check_hostname = False
                sc.verify_mode = ssl.CERT_NONE
                sc.minimum_version = ssl.TLSVersion.TLSv1_3
                sc.maximum_version = ssl.TLSVersion.TLSv1_3
                async with self._throttled(ctx):
                    _, w = await asyncio.wait_for(
                        asyncio.open_connection(
                            host, port, ssl=sc, server_hostname=host,
                        ),
                        timeout=_PROBE_TIMEOUT,
                    )
                w.close()
                await w.wait_closed()
                for name in tls13_std:
                    accepted.append(_build_cipher_detail(name, registry[name]))
            except (ssl.SSLError, TimeoutError, OSError, ConnectionError, ValueError):
                pass

        # PQC TLS 1.3 ciphers — need OQS-enabled OpenSSL; probe individually
        for name in tls13_pqc:
            try:
                sc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                sc.check_hostname = False
                sc.verify_mode = ssl.CERT_NONE
                sc.set_ciphers(name)
            except ssl.SSLError:
                continue
            try:
                async with self._throttled(ctx):
                    _, w = await asyncio.wait_for(
                        asyncio.open_connection(
                            host, port, ssl=sc, server_hostname=host,
                        ),
                        timeout=_PROBE_TIMEOUT,
                    )
                w.close()
                await w.wait_closed()
                accepted.append(_build_cipher_detail(name, registry[name]))
            except (ssl.SSLError, TimeoutError, OSError, ConnectionError):
                pass

        # Pre-1.3 ciphers — per-cipher probe, capped, with host concurrency
        cap = max(0, 30 - len(accepted))
        pre13 = pre13[:cap]
        host_sem = asyncio.Semaphore(5)

        async def _test(cipher_name: str) -> CipherDetail | None:
            try:
                sc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                sc.check_hostname = False
                sc.verify_mode = ssl.CERT_NONE
                sc.set_ciphers(cipher_name)
            except ssl.SSLError:
                return None
            try:
                async with host_sem:
                    async with self._throttled(ctx):
                        _, w = await asyncio.wait_for(
                            asyncio.open_connection(
                                host, port, ssl=sc, server_hostname=host,
                            ),
                            timeout=_PROBE_TIMEOUT,
                        )
                    w.close()
                    await w.wait_closed()
            except (ssl.SSLError, TimeoutError, OSError, ConnectionError):
                return None
            return _build_cipher_detail(cipher_name, registry.get(cipher_name, {}))

        # Phase 1 — first 10 (early-exit if server rejects every one)
        batch1 = pre13[:10]
        if batch1:
            results = await asyncio.gather(
                *[_test(n) for n in batch1], return_exceptions=True,
            )
            phase1 = [r for r in results if isinstance(r, CipherDetail)]
            accepted.extend(phase1)
            if not phase1:
                return accepted

        # Phase 2 — remaining
        batch2 = pre13[10:]
        if batch2:
            results = await asyncio.gather(
                *[_test(n) for n in batch2], return_exceptions=True,
            )
            accepted.extend(r for r in results if isinstance(r, CipherDetail))

        return accepted

    # ── 4. extract leaf certificate (+ negotiated cipher) ────────────

    async def _extract_cert(
        self, host: str, port: int, ctx: ScanContext,
    ) -> tuple[CertificateDetail | None, str | None]:
        """Return *(CertificateDetail, negotiated_cipher_name)*.

        Both elements may be ``None`` on failure.
        """
        sc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        sc.check_hostname = False
        sc.verify_mode = ssl.CERT_NONE

        try:
            async with self._throttled(ctx):
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host, port, ssl=sc, server_hostname=host,
                    ),
                    timeout=_PROBE_TIMEOUT,
                )
        except (ssl.SSLError, TimeoutError, OSError, ConnectionError):
            return None, None

        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is None:
                return None, None

            negotiated: str | None = None
            ci = ssl_obj.cipher()
            if ci:
                negotiated = ci[0]

            der = ssl_obj.getpeercert(binary_form=True)
            if der is None:
                return None, negotiated

            cert = x509.load_der_x509_certificate(der)
            now = datetime.now(timezone.utc)

            # Key type / size
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                key_type, key_size = "RSA", pub.key_size
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                key_type, key_size = "EC", pub.key_size
            else:
                key_type, key_size = "unknown", None

            # Signature algorithm
            try:
                sig_alg: str = cert.signature_algorithm_oid._name  # type: ignore[attr-defined]
            except AttributeError:
                sig_alg = cert.signature_algorithm_oid.dotted_string

            # Subject Alternative Names
            sans: list[str] = []
            try:
                ext = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName,
                )
                sans = ext.value.get_values_for_type(x509.DNSName)
            except (x509.ExtensionNotFound, Exception):
                pass

            # Validity window (compat shim for older cryptography builds)
            try:
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
            except AttributeError:
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)  # type: ignore[attr-defined]
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)  # type: ignore[attr-defined]

            days_left = (not_after - now).days

            detail = CertificateDetail(
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                serial=str(cert.serial_number),
                valid_from=not_before.isoformat(),
                valid_to=not_after.isoformat(),
                days_until_expiry=days_left,
                expired=days_left < 0,
                key_type=key_type,
                key_size=key_size,
                sig_algorithm=sig_alg,
                sans=sans,
                is_self_signed=(cert.issuer == cert.subject),
                fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(":"),
                quantum_vulnerable=key_type in ("RSA", "EC"),
            )
            return detail, negotiated

        except Exception as exc:
            logger.warning("cert parse error %s:%d — %s", host, port, exc)
            return None, None
        finally:
            writer.close()
            await writer.wait_closed()

    # ── 5. STARTTLS upgrade ──────────────────────────────────────────

    async def _check_starttls(
        self,
        host: str,
        port: int,
        service_name: str,
        ctx: ScanContext,
    ) -> TLSProfile | None:
        try:
            async with self._throttled(ctx):
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=_PROBE_TIMEOUT,
                )
        except (TimeoutError, OSError, ConnectionError):
            return None

        protocol: str | None = None
        try:
            # SMTP
            if port in (25, 587) or "smtp" in service_name:
                protocol = "smtp"
                await asyncio.wait_for(reader.readline(), timeout=5)
                writer.write(b"EHLO qshield\r\n")
                await writer.drain()
                for _ in range(20):
                    line = await asyncio.wait_for(reader.readline(), timeout=5)
                    if not line or line[3:4] == b" ":
                        break
                writer.write(b"STARTTLS\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readline(), timeout=5)
                if not resp.startswith(b"220"):
                    return None

            # IMAP
            elif port == 143 or "imap" in service_name:
                protocol = "imap"
                await asyncio.wait_for(reader.readline(), timeout=5)
                writer.write(b". STARTTLS\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readline(), timeout=5)
                if b"OK" not in resp.upper():
                    return None

            # POP3
            elif port == 110 or "pop" in service_name:
                protocol = "pop3"
                await asyncio.wait_for(reader.readline(), timeout=5)
                writer.write(b"STLS\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readline(), timeout=5)
                if not resp.startswith(b"+OK"):
                    return None

            else:
                return None

            # Upgrade the plain-text transport to TLS
            tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls_ctx.check_hostname = False
            tls_ctx.verify_mode = ssl.CERT_NONE

            await writer.start_tls(tls_ctx, server_hostname=host)
            ssl_obj = writer.get_extra_info("ssl_object")

            negotiated: str | None = None
            versions: dict[str, bool] = {
                "TLSv1": False,
                "TLSv1_1": False,
                "TLSv1_2": False,
                "TLSv1_3": False,
            }

            if ssl_obj:
                ci = ssl_obj.cipher()
                if ci:
                    negotiated = ci[0]
                ver_str = ssl_obj.version()
                if ver_str:
                    key = _VER_DOTTED_TO_KEY.get(ver_str)
                    if key:
                        versions[key] = True

            return TLSProfile(
                host=host,
                port=port,
                tls_versions_supported=versions,
                negotiated_cipher=negotiated,
                starttls_protocol=protocol,
                confidence="medium",
            )

        except Exception as exc:
            logger.debug("STARTTLS failed %s:%d — %s", host, port, exc)
            return None
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── 6. detect PQC signals ────────────────────────────────────────

    @staticmethod
    def _detect_pqc_signals(
        negotiated_cipher: str | None,
        ciphers: list[CipherDetail],
    ) -> list[str]:
        signals: list[str] = []
        seen: set[str] = set()

        def _check(value: str, source: str) -> None:
            low = value.lower()
            for ind in _PQC_INDICATORS:
                if ind in low:
                    tag = f"{source}:{ind}"
                    if tag not in seen:
                        seen.add(tag)
                        signals.append(tag)

        if negotiated_cipher:
            _check(negotiated_cipher, "negotiated")
        for c in ciphers:
            _check(c.name, "cipher")
            if c.kex:
                _check(c.kex, "kex")

        return signals

    # ── execute (pipeline entry-point) ───────────────────────────────

    async def execute(self, ctx: ScanContext) -> StageResult:
        profiles: list[dict] = []
        request_count = 0

        tls_targets: set[tuple[str, int]] = set()
        starttls_targets: list[tuple[str, int, str]] = []

        for svc in (ctx.services or []):
            host = svc.get("host") or svc.get("ip", "")
            port = svc.get("port", 0)
            svc_name = (svc.get("service_name") or "").lower()
            if not host or not port:
                continue
            if port in self._TLS_PORTS or "https" in svc_name or "ssl" in svc_name:
                tls_targets.add((host, port))
            if port in self._STARTTLS_PORTS:
                starttls_targets.append((host, port, svc_name))

        # ── Fallback: probe every discovered subdomain on 443 ──
        # This ensures TLS data is collected even when the network
        # stage returned no services (firewall, timeout, etc.).
        for sub in (ctx.subdomains or []):
            if isinstance(sub, str):
                host = sub.strip().lower()
            elif isinstance(sub, dict):
                host = (sub.get("hostname") or sub.get("subdomain") or "").strip().lower()
            else:
                host = str(sub).strip().lower()
            if host:
                tls_targets.add((host, 443))

        # Always include the root domain
        if ctx.domain:
            tls_targets.add((ctx.domain, 443))

        # ── Direct-TLS targets ──
        for host, port in tls_targets:
            try:
                versions = await self._probe_all_versions(host, port, ctx)
                request_count += sum(
                    1 for v in _TLS_VERSIONS.values() if v is not None
                )

                ciphers = await self._enumerate_ciphers(host, port, ctx)
                request_count += min(len(self._load_cipher_registry()), 30)

                cert_detail, negotiated = await self._extract_cert(host, port, ctx)
                request_count += 1

                pqc = self._detect_pqc_signals(negotiated, ciphers)

                profiles.append(
                    TLSProfile(
                        host=host,
                        port=port,
                        tls_versions_supported=versions,
                        accepted_ciphers=ciphers,
                        negotiated_cipher=negotiated,
                        leaf_cert=cert_detail,
                        cert_chain=[cert_detail] if cert_detail else [],
                        forward_secrecy=any(c.pfs for c in ciphers),
                        pqc_signals=pqc,
                        confidence="high",
                    ).model_dump()
                )
            except Exception as exc:
                logger.warning("TLS probe failed %s:%d — %s", host, port, exc)

        # ── STARTTLS targets (skip if already probed as direct TLS) ──
        for host, port, svc_name in starttls_targets:
            if (host, port) in tls_targets:
                continue
            try:
                sp = await self._check_starttls(host, port, svc_name, ctx)
                request_count += 1
                if sp:
                    profiles.append(sp.model_dump())
            except Exception as exc:
                logger.debug("STARTTLS check failed %s:%d — %s", host, port, exc)

        return StageResult(
            status="ok",
            data={"tls_profiles": profiles},
            request_count=request_count,
        )
