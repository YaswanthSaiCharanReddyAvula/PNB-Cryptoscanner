"""
QuantumShield — Surface Recon Engine (Stage 1)

Pure-Python reconnaissance: DNS enumeration, CT log mining, subdomain
brute-force, reverse DNS, WHOIS, zone-transfer detection, and email-security
record parsing.  No subprocess calls — uses dnspython + httpx + asyncio only.
"""

from __future__ import annotations

import asyncio
import re
import ssl
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.query
import dns.resolver
import dns.zone
import httpx

from app.config import settings
from app.scanner.models import DNSRecord, ReconResult, StageResult, WhoisInfo
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

_WORDLIST_PATH = Path(__file__).resolve().parent.parent / "data" / "subdomain_wordlist.txt"
_DNS_RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "CNAME")
_CT_TIMEOUT = 15
_CERTSPOTTER_TIMEOUT = 15
_WHOIS_TIMEOUT = 10
_ZT_TIMEOUT = 5

# Public DNS resolvers — used when the system resolver is unreliable.
_PUBLIC_DNS = [
    ["8.8.8.8", "8.8.4.4"],       # Google
    ["1.1.1.1", "1.0.0.1"],       # Cloudflare
    ["9.9.9.9", "149.112.112.112"],# Quad9
]

def _make_resolver(nameservers: list[str] | None = None,
                   lifetime: float = 8, timeout: float = 5
                   ) -> dns.asyncresolver.Resolver:
    """Create a resilient async DNS resolver.
    
    If *nameservers* is provided they override the system defaults.
    """
    r = dns.asyncresolver.Resolver()
    r.lifetime = lifetime
    r.timeout = timeout
    if nameservers:
        r.nameservers = nameservers
    return r

async def _resolve_with_fallback(
    qname: str, rdtype: str = "A", lifetime: float = 8, timeout: float = 5,
) -> dns.asyncresolver.Answer | None:
    """Try resolving with system DNS first, then public resolvers."""
    resolver_sets: list[list[str] | None] = [None] + _PUBLIC_DNS  # None = system default
    for ns in resolver_sets:
        try:
            r = _make_resolver(ns, lifetime=lifetime, timeout=timeout)
            return await r.resolve(qname, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return None  # definitive negative — no point retrying
        except (dns.exception.Timeout, Exception) as exc:
            label = ns[0] if ns else "system"
            logger.debug("DNS %s %s via %s failed: %s", rdtype, qname, label, exc)
            continue
    return None

# Second-pass brute-force: small targeted list for nested subdomains
_SECOND_PASS_WORDS = [
    "mta-sts", "mail", "smtp", "api", "www", "dev",
    "staging", "admin", "vpn", "cdn", "ns1", "ns2",
    "secure", "login", "sso", "gateway", "portal",
    "m", "mobile", "internal", "test", "docs",
    "status", "monitor", "autodiscover",
]


class SurfaceReconEngine(ScanStage):
    name = "recon"
    order = 1
    timeout_seconds = 120
    criticality = StageCriticality.CRITICAL
    required_fields: list[str] = []
    writes_fields = ["subdomains", "ip_map", "dns_records", "whois"]
    merge_strategy = MergeStrategy.OVERWRITE

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    async def execute(self, ctx: ScanContext) -> StageResult:
        domain = ctx.domain.lower().strip().strip(".")
        request_count = 0

        try:
            # ── Phase 1 — Parallel passive sources ────────────────────
            dns_task = asyncio.create_task(self._sweep_dns(domain, ctx))
            ct_task = (
                asyncio.create_task(self._mine_ct_logs(domain, ctx))
                if settings.SCANNER_ENABLE_CT_LOGS
                else None
            )
            cs_task = (
                asyncio.create_task(self._mine_certspotter(domain, ctx))
                if settings.SCANNER_ENABLE_CT_LOGS
                else None
            )

            gather_tasks = [dns_task]
            if ct_task:
                gather_tasks.append(ct_task)
            if cs_task:
                gather_tasks.append(cs_task)

            results = await asyncio.gather(*gather_tasks, return_exceptions=True)

            dns_records = results[0] if not isinstance(results[0], BaseException) else []
            if isinstance(results[0], BaseException):
                logger.warning("DNS sweep failed: %s", results[0])
                dns_records = []

            ct_hosts: list[str] = []
            cs_hosts: list[str] = []
            idx = 1
            if ct_task:
                ct_hosts = results[idx] if not isinstance(results[idx], BaseException) else []
                if isinstance(results[idx], BaseException):
                    logger.warning("CT log mining failed: %s", results[idx])
                idx += 1
            if cs_task:
                cs_hosts = results[idx] if not isinstance(results[idx], BaseException) else []
                if isinstance(results[idx], BaseException):
                    logger.warning("CertSpotter failed: %s", results[idx])

            request_count += len(dns_records) + (2 if ct_hosts else 0) + (1 if cs_hosts else 0)

            # ── Phase 2 — Dictionary-based subdomain brute-force ──────
            dict_hosts = await self._enumerate_subdomains(domain, ctx)
            request_count += len(dict_hosts)

            # ── Phase 3 — Merge all hostname sources ──────────────────
            extra_hosts = self._extract_hostnames_from_dns(dns_records, domain)
            spf_hosts = self._walk_spf(domain, dns_records)
            all_candidates: set[str] = set()
            all_candidates.update(h.lower() for h in ct_hosts)
            all_candidates.update(h.lower() for h in cs_hosts)
            all_candidates.update(h.lower() for h in dict_hosts)
            all_candidates.update(h.lower() for h in extra_hosts)
            all_candidates.update(h.lower() for h in spf_hosts)

            # ── Phase 3b — Iterative TLS SAN harvesting (up to 3 rounds)
            for san_round in range(3):
                seed_hosts = [domain] + sorted(all_candidates)
                san_hosts = await self._extract_tls_san_hosts(domain, seed_hosts, ctx)
                new_sans = san_hosts - all_candidates
                request_count += len(seed_hosts)
                if not new_sans:
                    break
                logger.info(
                    "SAN round %d: discovered %d new hosts",
                    san_round + 1, len(new_sans),
                )
                all_candidates.update(new_sans)

            all_candidates.discard("")

            max_subs = ctx.options.get("max_subdomains")
            candidates = sorted(all_candidates)
            if isinstance(max_subs, int) and max_subs > 0:
                candidates = candidates[:max_subs]

            # ── Phase 4 — DNS liveness check ──────────────────────────
            live_hosts = await self._liveness_check(candidates, ctx)
            request_count += len(candidates)

            if domain not in live_hosts:
                live_hosts.insert(0, domain)

            # ── Phase 4b — Second-pass brute-force on live subdomains ─
            second_pass = await self._second_pass_brute_force(
                live_hosts, domain, ctx,
            )
            if second_pass:
                new_live = await self._liveness_check(second_pass, ctx)
                request_count += len(second_pass)
                for h in new_live:
                    if h not in live_hosts:
                        live_hosts.append(h)
                        logger.info("Second-pass discovered: %s", h)

            # ── Phase 5 — Resolve IPs ─────────────────────────────────
            ip_map = await self._resolve_ips(live_hosts, ctx)
            request_count += len(live_hosts)

            # ── Phase 6 — Reverse DNS on unique IPs ───────────────────
            unique_ips: set[str] = set()
            for ips in ip_map.values():
                unique_ips.update(ips)
            reverse_map = await self._reverse_dns(unique_ips, ctx)
            request_count += len(unique_ips)

            # Phase 6b — Recover subdomains from reverse DNS
            for ip, ptr_hostname in reverse_map.items():
                ptr_host = ptr_hostname.lower().strip(".")
                if (ptr_host == domain or ptr_host.endswith(f".{domain}")) \
                   and ptr_host not in live_hosts:
                    live_hosts.append(ptr_host)
                    logger.info("Recovered subdomain from PTR: %s -> %s", ip, ptr_host)

            # ── Phase 7 — optional WHOIS ──────────────────────────────
            whois_info = None
            if settings.SCANNER_ENABLE_WHOIS:
                whois_info = await self._query_whois(domain)
                request_count += 1

            # ── Phase 8 — Zone transfer attempt ───────────────────────
            ns_list = [
                r.value for r in dns_records if r.record_type == "NS"
            ]
            zone_vuln = await self._attempt_zone_transfer(domain, ns_list)
            request_count += len(ns_list) or 1

            # ── Phase 9 — Email security records ──────────────────────
            spf, dmarc = await self._parse_email_security(domain, dns_records)
            request_count += 1

            # Re-resolve IPs for any newly added hosts from PTR recovery
            ip_map = await self._resolve_ips(live_hosts, ctx)

            # Build result
            all_ct = sorted(set(ct_hosts + cs_hosts))
            recon = ReconResult(
                subdomains=live_hosts,
                ip_map=ip_map,
                dns_records=dns_records,
                whois=whois_info,
                ct_hosts=all_ct,
                reverse_dns=reverse_map,
                zone_transfer_vulnerable=zone_vuln,
                spf_record=spf,
                dmarc_record=dmarc,
            )

            dns_as_dicts = [r.model_dump() for r in dns_records]
            whois_dict = whois_info.model_dump() if whois_info else None

            return StageResult(
                status="ok",
                data={
                    "subdomains": live_hosts,
                    "ip_map": ip_map,
                    "dns_records": dns_as_dicts,
                    "whois": whois_dict,
                    "recon_full": recon.model_dump(),
                },
                request_count=request_count,
            )

        except Exception as exc:
            logger.exception("Recon stage crashed")
            return StageResult(
                status="error",
                error=str(exc),
                request_count=request_count,
            )

    # ------------------------------------------------------------------
    # 1. DNS record sweep
    # ------------------------------------------------------------------

    async def _sweep_dns(
        self, domain: str, ctx: ScanContext,
    ) -> list[DNSRecord]:
        records: list[DNSRecord] = []

        for rtype in _DNS_RECORD_TYPES:
            try:
                async with ctx.throttle.acquire("dns"):
                    answer = await _resolve_with_fallback(domain, rtype)
                if answer is None:
                    continue
                for rr in answer:
                    records.append(DNSRecord(
                        hostname=domain,
                        record_type=rtype,
                        value=rr.to_text(),
                        ttl=answer.rrset.ttl if answer.rrset else None,
                    ))
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                pass
            except Exception as exc:
                logger.debug("DNS %s query for %s failed: %s", rtype, domain, exc)

        return records

    # ------------------------------------------------------------------
    # 2. Certificate-Transparency log mining
    # ------------------------------------------------------------------

    async def _mine_ct_logs(
        self, domain: str, ctx: ScanContext,
    ) -> list[str]:
        base_url = "https://crt.sh/"
        queries = (f"%.{domain}", domain)
        entries: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=_CT_TIMEOUT, follow_redirects=True,
        ) as client:
            for q in queries:
                try:
                    async with ctx.throttle.acquire("http_probe"):
                        resp = await client.get(
                            base_url, params={"q": q, "output": "json"},
                        )
                    if resp.status_code == 404:
                        continue
                    resp.raise_for_status()
                    payload = resp.json()
                    if isinstance(payload, list):
                        entries.extend(payload)
                except Exception as exc:
                    logger.warning(
                        "CT log query failed for %s (q=%s): %s", domain, q, exc,
                    )

        if not entries:
            return []

        hostnames: set[str] = set()
        for entry in entries:
            for name in str(entry.get("name_value", "")).split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name and (name == domain or name.endswith(f".{domain}")):
                    hostnames.add(name)

        return sorted(hostnames)

    # ------------------------------------------------------------------
    # 3. Dictionary-based subdomain enumeration
    # ------------------------------------------------------------------

    async def _enumerate_subdomains(
        self, domain: str, ctx: ScanContext,
    ) -> list[str]:
        try:
            words = _WORDLIST_PATH.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            logger.warning("Subdomain wordlist not found at %s", _WORDLIST_PATH)
            return []

        max_subs = ctx.options.get("max_subdomains")
        words = [w.strip() for w in words if w.strip()]
        if isinstance(max_subs, int) and max_subs > 0:
            words = words[:max_subs]

        async def _probe(word: str) -> str | None:
            fqdn = f"{word}.{domain}"
            try:
                async with ctx.throttle.acquire("dns"):
                    ans = await _resolve_with_fallback(fqdn, "A", lifetime=5, timeout=3)
                    if ans:
                        return fqdn
                    ans = await _resolve_with_fallback(fqdn, "AAAA", lifetime=5, timeout=3)
                    if ans:
                        return fqdn
                return None
            except Exception:
                return None

        results = await asyncio.gather(*(_probe(w) for w in words))
        return [r for r in results if r is not None]

    # ------------------------------------------------------------------
    # 4. IP resolution
    # ------------------------------------------------------------------

    async def _resolve_ips(
        self, subdomains: list[str], ctx: ScanContext,
    ) -> dict[str, list[str]]:
        ip_map: dict[str, list[str]] = {}

        async def _resolve_one(host: str) -> tuple[str, list[str]]:
            ips: list[str] = []
            try:
                async with ctx.throttle.acquire("dns"):
                    answer = await _resolve_with_fallback(host, "A", lifetime=5, timeout=3)
                if answer:
                    ips = [rr.to_text() for rr in answer]
            except Exception:
                pass
            try:
                async with ctx.throttle.acquire("dns"):
                    answer6 = await _resolve_with_fallback(host, "AAAA", lifetime=5, timeout=3)
                if answer6:
                    ips.extend(rr.to_text() for rr in answer6)
            except Exception:
                pass
            return host, ips

        pairs = await asyncio.gather(*(_resolve_one(h) for h in subdomains))
        for host, ips in pairs:
            if ips:
                ip_map[host] = ips

        return ip_map

    # ------------------------------------------------------------------
    # 5. Reverse DNS (PTR)
    # ------------------------------------------------------------------

    async def _reverse_dns(
        self, ips: set[str], ctx: ScanContext,
    ) -> dict[str, str]:
        result: dict[str, str] = {}

        async def _ptr(ip: str) -> tuple[str, str | None]:
            try:
                parts = ip.split(".")
                arpa = ".".join(reversed(parts)) + ".in-addr.arpa"
                async with ctx.throttle.acquire("dns"):
                    answer = await _resolve_with_fallback(arpa, "PTR", lifetime=5, timeout=3)
                if answer:
                    return ip, answer[0].to_text().rstrip(".")
                return ip, None
            except Exception:
                return ip, None

        pairs = await asyncio.gather(*(_ptr(ip) for ip in ips))
        for ip, hostname in pairs:
            if hostname:
                result[ip] = hostname

        return result

    # ------------------------------------------------------------------
    # 6. WHOIS (raw TCP, no external library)
    # ------------------------------------------------------------------

    async def _query_whois(self, domain: str) -> WhoisInfo | None:
        try:
            raw = await self._whois_raw(domain, "whois.iana.org")

            referral = None
            for line in raw.splitlines():
                if line.lower().startswith("refer:"):
                    referral = line.split(":", 1)[1].strip()
                    break

            if referral:
                raw = await self._whois_raw(domain, referral)
            else:
                # Fallback for registries that do not include IANA referral.
                tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
                fallback_servers = {
                    "com": "whois.verisign-grs.com",
                    "net": "whois.verisign-grs.com",
                    "org": "whois.pir.org",
                    "io": "whois.nic.io",
                    "in": "whois.registry.in",
                }
                if fallback := fallback_servers.get(tld):
                    raw = await self._whois_raw(domain, fallback)

            return self._parse_whois(domain, raw)
        except Exception as exc:
            logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
            return None

    async def _whois_raw(self, domain: str, server: str) -> str:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, 43),
            timeout=_WHOIS_TIMEOUT,
        )
        try:
            writer.write(f"{domain}\r\n".encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(8192), timeout=_WHOIS_TIMEOUT)
            return data.decode("utf-8", errors="replace")
        finally:
            writer.close()
            await writer.wait_closed()

    @staticmethod
    def _parse_whois(domain: str, raw: str) -> WhoisInfo:
        def _extract(pattern: str) -> str | None:
            m = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
            return m.group(1).strip() if m else None

        registrar = _extract(r"registrar:\s*(.+)")
        creation = _extract(r"creat(?:ion|ed)\s*date:\s*(.+)")
        expiry = _extract(r"(?:expir(?:y|ation)\s*date|paid-till):\s*(.+)")

        ns_matches = re.findall(
            r"name\s*server:\s*(.+)", raw, re.IGNORECASE | re.MULTILINE,
        )
        nameservers = [ns.strip().rstrip(".").lower() for ns in ns_matches]

        dnssec_val = _extract(r"dnssec:\s*(.+)")
        dnssec = bool(dnssec_val and "signed" in dnssec_val.lower())

        return WhoisInfo(
            domain=domain,
            registrar=registrar,
            creation_date=creation,
            expiry_date=expiry,
            nameservers=nameservers,
            dnssec=dnssec,
        )

    # ------------------------------------------------------------------
    # 7. Zone transfer attempt
    # ------------------------------------------------------------------

    async def _attempt_zone_transfer(
        self, domain: str, ns_list: list[str],
    ) -> bool:
        if not ns_list:
            return False

        loop = asyncio.get_running_loop()

        async def _try_ns(ns: str) -> bool:
            try:
                xfr = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: dns.zone.from_xfr(
                            dns.query.xfr(ns, domain, timeout=_ZT_TIMEOUT),
                        ),
                    ),
                    timeout=_ZT_TIMEOUT + 2,
                )
                if xfr:
                    logger.warning(
                        "Zone transfer SUCCEEDED for %s via %s", domain, ns,
                    )
                    return True
            except Exception:
                pass
            return False

        results = await asyncio.gather(*(_try_ns(ns) for ns in ns_list))
        return any(results)

    # ------------------------------------------------------------------
    # 8. Email security (SPF + DMARC)
    # ------------------------------------------------------------------

    async def _parse_email_security(
        self, domain: str, dns_records: list[DNSRecord],
    ) -> tuple[str | None, str | None]:
        spf: str | None = None
        for rec in dns_records:
            if rec.record_type == "TXT" and rec.value.lower().startswith('"v=spf1'):
                spf = rec.value.strip('"')
                break
            if rec.record_type == "TXT" and rec.value.lower().startswith("v=spf1"):
                spf = rec.value
                break

        dmarc: str | None = None
        try:
            answer = await _resolve_with_fallback(f"_dmarc.{domain}", "TXT", lifetime=5, timeout=3)
            if answer:
                for rr in answer:
                    txt = rr.to_text().strip('"')
                    if txt.lower().startswith("v=dmarc1"):
                        dmarc = txt
                        break
        except Exception:
            pass

        return spf, dmarc

    # ------------------------------------------------------------------
    # 9. CertSpotter CT log source
    # ------------------------------------------------------------------

    async def _mine_certspotter(
        self, domain: str, ctx: ScanContext,
    ) -> list[str]:
        """Query CertSpotter API for subdomains (no API key needed)."""
        url = "https://api.certspotter.com/v1/issuances"
        try:
            async with httpx.AsyncClient(
                timeout=_CERTSPOTTER_TIMEOUT, follow_redirects=True,
            ) as client:
                async with ctx.throttle.acquire("http_probe"):
                    resp = await client.get(url, params={
                        "domain": domain,
                        "include_subdomains": "true",
                        "expand": "dns_names",
                    })
                if resp.status_code != 200:
                    return []
                hostnames: set[str] = set()
                for entry in resp.json():
                    for name in entry.get("dns_names", []):
                        name = name.strip().lstrip("*.").lower()
                        if name and (name == domain or name.endswith(f".{domain}")):
                            hostnames.add(name)
                return sorted(hostnames)
        except Exception as exc:
            logger.warning("CertSpotter failed for %s: %s", domain, exc)
            return []

    # ------------------------------------------------------------------
    # 10. Second-pass brute-force for nested subdomains
    # ------------------------------------------------------------------

    async def _second_pass_brute_force(
        self,
        live_subdomains: list[str],
        root_domain: str,
        ctx: ScanContext,
    ) -> list[str]:
        """Brute-force second-level subdomains under each known subdomain."""
        found: set[str] = set()
        already_known = set(live_subdomains)

        async def _probe(fqdn: str) -> str | None:
            try:
                async with ctx.throttle.acquire("dns"):
                    ans = await _resolve_with_fallback(fqdn, "A", lifetime=4, timeout=2)
                return fqdn if ans else None
            except Exception:
                return None

        tasks = []
        for sub in live_subdomains:
            if sub == root_domain:
                continue
            for word in _SECOND_PASS_WORDS:
                fqdn = f"{word}.{sub}"
                if fqdn not in already_known and fqdn not in found:
                    found.add(fqdn)  # track to prevent duplicate probes
                    tasks.append(_probe(fqdn))

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, str) and r]

    # ------------------------------------------------------------------
    # 11. SPF record walking
    # ------------------------------------------------------------------

    @staticmethod
    def _walk_spf(domain: str, dns_records: list[DNSRecord]) -> set[str]:
        """Extract hostnames from SPF include/a/mx directives."""
        hosts: set[str] = set()
        for rec in dns_records:
            if rec.record_type != "TXT":
                continue
            val = rec.value.strip('"')
            if not val.lower().startswith("v=spf1"):
                continue
            for m in re.finditer(r'(?:include|a|mx):([^\s]+)', val, re.IGNORECASE):
                name = m.group(1).rstrip(".").lower()
                if name == domain or name.endswith(f".{domain}"):
                    hosts.add(name)
        return hosts

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_hostnames_from_dns(
        records: list[DNSRecord], domain: str,
    ) -> set[str]:
        """Pull resolvable hostnames out of MX/NS/CNAME/SRV values."""
        hosts: set[str] = set()
        for rec in records:
            if rec.record_type in ("MX", "NS", "CNAME", "SRV"):
                val = rec.value.rstrip(".")
                if rec.record_type == "MX":
                    parts = val.split()
                    val = parts[-1].rstrip(".") if parts else ""
                if rec.record_type == "SRV":
                    parts = val.split()
                    val = parts[-1].rstrip(".") if parts else ""
                val = val.lower()
                if val and (val == domain or val.endswith(f".{domain}")):
                    hosts.add(val)
        return hosts

    async def _liveness_check(
        self, candidates: list[str], ctx: ScanContext,
    ) -> list[str]:
        """Confirm candidate hosts resolve using A/AAAA/CNAME checks."""

        async def _check(host: str) -> str | None:
            try:
                async with ctx.throttle.acquire("dns"):
                    ans = await _resolve_with_fallback(host, "A", lifetime=4, timeout=2)
                    if ans:
                        return host
                    ans = await _resolve_with_fallback(host, "AAAA", lifetime=4, timeout=2)
                    if ans:
                        return host
                    ans = await _resolve_with_fallback(host, "CNAME", lifetime=4, timeout=2)
                    if ans:
                        return host
                return None
            except Exception:
                return None

        results = await asyncio.gather(*(_check(h) for h in candidates))
        return [h for h in results if h is not None]

    async def _extract_tls_san_hosts(
        self,
        domain: str,
        seed_hosts: list[str],
        ctx: ScanContext,
    ) -> set[str]:
        """Harvest subdomains from TLS SAN entries on reachable HTTPS hosts.

        Uses getpeercert(binary_form=True) + cryptography.x509 because
        Python's getpeercert() returns {} when verify_mode=CERT_NONE.
        """
        from cryptography import x509

        hosts: set[str] = set()

        async def _probe(host: str) -> None:
            try:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                async with ctx.throttle.acquire("http_probe"):
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            host=host,
                            port=443,
                            ssl=ssl_ctx,
                            server_hostname=host,
                        ),
                        timeout=4,
                    )
                try:
                    ssl_obj = writer.get_extra_info("ssl_object")
                    if ssl_obj is None:
                        return
                    der_cert = ssl_obj.getpeercert(binary_form=True)
                    if not der_cert:
                        return
                    cert = x509.load_der_x509_certificate(der_cert)
                    try:
                        san_ext = cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName,
                        )
                        for name in san_ext.value.get_values_for_type(x509.DNSName):
                            name = str(name).strip().lstrip("*.").lower()
                            if name and (name == domain or name.endswith(f".{domain}")):
                                hosts.add(name)
                    except x509.ExtensionNotFound:
                        pass
                finally:
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                return

        await asyncio.gather(*(_probe(h) for h in seed_hosts), return_exceptions=True)
        return hosts
