import asyncio
import json
import re
import socket
import tempfile
import os
import uuid
import time
from typing import List, Set
from asyncio.subprocess import PIPE

import dns.resolver
from app.db.models import DiscoveredAsset, NameServerInfo
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def _run_command(cmd: List[str], name: str = "Command", timeout: int | None = None) -> str:
    """Run an external command asynchronously with a 30s heartbeat log."""
    timeout = timeout or settings.TOOL_TIMEOUT
    logger.info("Starting tool [%s]: %s (Timeout: %ds)", name, " ".join(cmd), timeout)
    start_time = time.time()
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=PIPE,
            stderr=PIPE,
        )
        
        # Monitor progress every 30 seconds
        while True:
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=30
                )
                # If we get here, the process finished
                duration = time.time() - start_time
                logger.info("Tool [%s] finished in %.2fs", name, duration)
                
                if stderr:
                    err_msg = stderr.decode(errors="replace").strip()
                    if err_msg:
                        logger.warning("stderr from %s: %s", name, err_msg)
                
                return stdout.decode(errors="replace")
                
            except asyncio.TimeoutError:
                # Still running...
                duration = time.time() - start_time
                if duration >= timeout:
                    logger.error("Tool [%s] timed out after %.2fs", name, duration)
                    try: process.kill()
                    except: pass
                    return ""
                
                progress_msg = f"Still running [{name}]... (Duration: {int(duration)}s)"
                logger.info(progress_msg)
                continue
            
    except FileNotFoundError:
        logger.error("Tool not found: %s — is it installed?", cmd[0])
        return ""
    except Exception as exc:
        logger.error("Tool [%s] failed (%s): %s", name, cmd[0], exc)
        return ""
    
    return ""


async def run_subfinder(domain: str) -> Set[str]:
    """Passive domain discovery using Subfinder."""
    logger.info("Running Subfinder (Passive) for %s...", domain)
    output = await _run_command(
        ["subfinder", "-d", domain, "-silent", "-r", "8.8.8.8,1.1.1.1",
         "--max-time", "30"],
        name="Subfinder",
        timeout=35,
    )
    subs = set()
    if output.strip():
        for line in output.splitlines():
            line = line.strip()
            if line and " " not in line:
                subs.add(line)
    return subs


async def run_amass(domain: str) -> Set[str]:
    """Deep enumeration using Amass."""
    logger.info("Running Amass (Deep) for %s...", domain)
    output = await _run_command(
        ["amass", "enum", "-passive", "-d", domain], 
        name="Amass", 
        timeout=60
    )
    subs = set()
    if output.strip():
        domain_pattern = re.compile(rf'([a-zA-Z0-9.-]+\.{re.escape(domain)})')
        subs.update(domain_pattern.findall(output))
    return subs


async def run_dnsx(subdomains: List[str]) -> List[str]:
    """Verify live domains using dnsx."""
    if not subdomains:
        return []
    
    logger.info("Running DNSX on %d potential subdomains...", len(subdomains))
    temp_target = os.path.join(tempfile.gettempdir(), f"dnsx_{uuid.uuid4().hex}.txt")
    
    try:
        with open(temp_target, "w") as f:
            f.write("\n".join(subdomains))
            
        output = await _run_command(
            ["dnsx", "-l", temp_target, "-silent", "-resp-only", "-r", "8.8.8.8,1.1.1.1"], 
            name="DNSX"
        )
        
        live = []
        domain_regex = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        for line in output.splitlines():
            line = line.strip()
            if line and domain_regex.match(line) and "error" not in line.lower():
                live.append(line)
        return list(set(live))
    except Exception as exc:
        logger.error("DNSX failed: %s", exc)
        return []
    finally:
        if os.path.exists(temp_target):
            try: os.remove(temp_target)
            except: pass
            
    return []


async def run_httpx(subdomains: List[str]) -> List[str]:
    """Find running web services using httpx."""
    if not subdomains:
        return []
    
    logger.info("Running HTTPX on %d live subdomains...", len(subdomains))
    temp_target = os.path.join(tempfile.gettempdir(), f"httpx_{uuid.uuid4().hex}.txt")
    
    try:
        with open(temp_target, "w") as f:
            f.write("\n".join(subdomains))
            
        # Try standard httpx first
        cmd = ["httpx", "-l", temp_target, "-silent"]
        logger.info("Probing web services with Tool [HTTPX]...")
        output = await _run_command(cmd, name="HTTPX")
        
        # Fallback to httpx-toolkit if no output (common Kali naming conflict)
        if not output.strip():
            logger.info("HTTPX returned no output, trying [httpx-toolkit] fallback...")
            cmd[0] = "httpx-toolkit"
            output = await _run_command(cmd, name="HTTPX-Toolkit")
        
        active_web = []
        domain_regex = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
                
            host = line.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
            if host and domain_regex.match(host) and "error" not in host.lower():
                active_web.append(host)
                
        return list(set(active_web))
    except Exception as exc:
        logger.error("HTTPX failed: %s", exc)
        return []
    finally:
        if os.path.exists(temp_target):
            try: os.remove(temp_target)
            except: pass


async def scan_ports(target: str, ports: str | None = None) -> List[int]:
    """Scan ports with nmap."""
    ports = ports or settings.DEFAULT_PORTS
    output = await _run_command([
        "nmap", "-Pn", "-sT", "-p", ports, "--open", "-oG", "-", target
    ], name=f"Nmap-{target}")

    open_ports: List[int] = []
    if not output or "Failed to resolve" in output:
        logger.warning(f"Nmap failed to resolve or scan {target}. Attempting default ports.")
        return [443]

    for line in output.splitlines():
        port_matches = re.findall(r"(\d+)/open", line)
        open_ports.extend(int(p) for p in port_matches)

    return open_ports if open_ports else [443]


async def get_ns_records(domain: str) -> List[NameServerInfo]:
    """Fetch Name Server (NS) records for a domain."""
    logger.info("Fetching NS records for %s", domain)
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        answers = resolver.resolve(domain, 'NS')
        
        records = []
        for rdata in answers:
            ns_host = str(rdata.target).rstrip('.')
            try:
                ns_ip = socket.gethostbyname(ns_host)
            except:
                ns_ip = None
                
            records.append(NameServerInfo(
                hostname=ns_host,
                type="NS",
                ip_address=ns_ip,
                ttl=answers.ttl
            ))
        return records
    except Exception as exc:
        logger.error("Failed to fetch NS records for %s: %s", domain, exc)
        return []


async def discover_assets(domain: str, ports: str | None = None, broadcast_func = None) -> List[DiscoveredAsset]:
    """
    Refined Pipeline: Subfinder -> Amass -> DNSX -> HTTPX -> Nmap.
    """
    async def log_and_broadcast(msg: str):
        logger.info(msg)
        if broadcast_func:
            await broadcast_func(msg)

    domain_regex = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    if not domain_regex.match(domain):
        log_and_broadcast(f"Invalid domain format rejected by pipeline: {domain}")
        return []

    # 1. Discovery (Passive + Deep)
    await log_and_broadcast(f"=== Starting discovery Phase for {domain} ===")
    
    await log_and_broadcast("Running Subfinder and Amass (Search Phase)...")
    subfinder_res, amass_res = await asyncio.gather(
        run_subfinder(domain),
        run_amass(domain)
    )
    all_subs = list(subfinder_res | amass_res)
    if not all_subs:
        all_subs = [domain]

    if len(all_subs) > settings.MAX_SUBDOMAINS:
        logger.info("Capping %d subdomains to MAX_SUBDOMAINS=%d", len(all_subs), settings.MAX_SUBDOMAINS)
        all_subs = all_subs[:settings.MAX_SUBDOMAINS]
    
    # 2. DNSX (Live Check)
    await log_and_broadcast(f"Found {len(all_subs)} potential domains. Verifying live hosts with DNSX...")
    live_subs = await run_dnsx(all_subs)
    if not live_subs:
        await log_and_broadcast(f"DNSX found no live hosts, using all discovered subdomains as fallback.")
        live_subs = list(all_subs) if all_subs else [domain]

    # 3. HTTPX (Web Services)
    await log_and_broadcast(f"Probing {len(live_subs)} live hosts for web services with HTTPX...")
    web_hosts = await run_httpx(live_subs)
    targets = web_hosts if web_hosts else live_subs
    
    clean_targets = []
    for t in targets:
        if domain_regex.match(t) and "error" not in t.lower() and "dependency" not in t.lower() and "client" not in t.lower():
            clean_targets.append(t)
    targets = clean_targets

    # 4. Nmap (Port Scan)
    await log_and_broadcast(f"Starting Nmap port scan for {len(targets)} targets...")
    assets: List[DiscoveredAsset] = []
    
    for i, target in enumerate(targets):
        progress = ((i + 1) / len(targets)) * 100
        msg = f"[Nmap Progress] Scanning {target} ({i + 1}/{len(targets)}) - {progress:.1f}% complete"
        await log_and_broadcast(msg)
        
        try:
            open_ports = await scan_ports(target, ports)
            ip = socket.gethostbyname(target)
        except:
            open_ports = [443]
            ip = "unknown"

        assets.append(DiscoveredAsset(
            subdomain=target,
            ip=ip,
            open_ports=open_ports
        ))

    await log_and_broadcast(f"=== Discovery complete: {len(assets)} assets found ===")
    return assets
