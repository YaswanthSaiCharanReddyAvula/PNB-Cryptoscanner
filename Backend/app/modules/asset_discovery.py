import asyncio
import json
import re
import socket
import tempfile
import os
import uuid
import time
from typing import List, Set

from app.db.models import DiscoveredAsset
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
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
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
                
                if stderr and b"error" in stderr.lower():
                    logger.warning("stderr from %s: %s", name, stderr.decode(errors="replace")[:500])
                
                return stdout.decode(errors="replace")
                
            except asyncio.TimeoutError:
                # Still running...
                duration = time.time() - start_time
                if duration >= timeout:
                    logger.error("Tool [%s] timed out after %.2fs", name, duration)
                    try: process.kill()
                    except: pass
                    return ""
                
                # Report "still running" and estimated progress if it's a known time-bound tool
                # For generic tools, we just show duration.
                progress_msg = f"Still running [{name}]... (Duration: {int(duration)}s)"
                logger.info(progress_msg)
                continue
            
    except FileNotFoundError:
        logger.error("Tool not found: %s — is it installed?", cmd[0])
        return ""
    except Exception as exc:
        logger.error("Tool [%s] failed (%s): %s", name, cmd[0], exc)
        return ""


async def run_subfinder(domain: str) -> Set[str]:
    """Passive domain discovery using Subfinder."""
    logger.info("Running Subfinder (Passive) for %s...", domain)
    output = await _run_command(
        ["subfinder", "-d", domain, "-silent"], 
        name="Subfinder"
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
    # We use active mode for "deep" enumeration if needed, but here we stay with passive+ 
    # to avoid excessive noise unless user specifically asks for active.
    # Adding '-passive' for now as it's the safest 'deep' starting point.
    output = await _run_command(
        ["amass", "enum", "-passive", "-d", domain], 
        name="Amass", 
        timeout=settings.TOOL_TIMEOUT * 2 # Give Amass more time
    )
    subs = set()
    if output.strip():
        # Amass output can be messy, use regex to pull domains ending in our target
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
            ["dnsx", "-l", temp_target, "-silent", "-resp-only"], 
            name="DNSX"
        )
        
        live = [line.strip() for line in output.splitlines() if line.strip()]
        return list(set(live))
    except Exception as exc:
        logger.error("DNSX failed: %s", exc)
        return []
    finally:
        if os.path.exists(temp_target):
            try: os.remove(temp_target)
            except: pass


async def run_httpx(subdomains: List[str]) -> List[str]:
    """Find running web services using httpx."""
    if not subdomains:
        return []
    
    logger.info("Running HTTPX on %d live subdomains...", len(subdomains))
    temp_target = os.path.join(tempfile.gettempdir(), f"httpx_{uuid.uuid4().hex}.txt")
    
    try:
        with open(temp_target, "w") as f:
            f.write("\n".join(subdomains))
            
        output = await _run_command(
            ["httpx", "-l", temp_target, "-silent"], 
            name="HTTPX"
        )
        
        # Extract hosts from URLs (httpx returns full URLs)
        active_web = []
        for line in output.splitlines():
            line = line.strip()
            if line:
                host = line.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
                if host:
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
    for line in output.splitlines():
        port_matches = re.findall(r"(\d+)/open", line)
        open_ports.extend(int(p) for p in port_matches)

    return open_ports if open_ports else [443]


async def discover_assets(domain: str, ports: str | None = None) -> List[DiscoveredAsset]:
    """
    Refined Pipeline: Subfinder -> Amass -> DNSX -> HTTPX -> Nmap.
    """
    # 1. Discovery (Passive + Deep)
    logger.info("=== Starting discovery Phase for %s ===", domain)
    subfinder_res, amass_res = await asyncio.gather(
        run_subfinder(domain),
        run_amass(domain)
    )
    all_subs = list(subfinder_res | amass_res)
    if not all_subs:
        all_subs = [domain]
    
    # 2. DNSX (Live Check)
    live_subs = await run_dnsx(all_subs)
    if not live_subs:
        logger.warning("DNSX found no live hosts, using root domain as fallback.")
        live_subs = [domain]

    # 3. HTTPX (Web Services)
    web_hosts = await run_httpx(live_subs)
    targets = web_hosts if web_hosts else live_subs

    # 4. Nmap (Port Scan)
    logger.info("Starting Nmap port scan for %d targets...", len(targets))
    assets: List[DiscoveredAsset] = []
    
    for i, target in enumerate(targets):
        progress = ((i + 1) / len(targets)) * 100
        logger.info("[Nmap Progress] Scanning %s (%d/%d) - %.1f%% complete", 
                    target, i + 1, len(targets), progress)
        
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

    logger.info("=== Discovery complete: %d assets found ===", len(assets))
    return assets

