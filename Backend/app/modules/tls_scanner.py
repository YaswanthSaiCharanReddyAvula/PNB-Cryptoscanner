"""
QuantumShield — Enhanced TLS Scanner

Extends the base TLS scanner with:
  - All supported TLS protocol versions (via sslscan)
  - All supported cipher suites enumeration (via sslscan/testssl)
  - Forward secrecy detection
  - Certificate chain validation
  - Certificate expiry alerts
  - Multi-tool validation consensus (testssl, sslscan, zgrab2, openssl)
"""

import asyncio
import json
import os
import re
import tempfile
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from app.db.models import CertChainEntry, CertificateInfo, TLSInfo, ConfidenceLevel
from app.config import settings
from app.modules.tls_pqc_signals import enrich_tls_info
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def _run_command(cmd: List[str], timeout: int | None = None) -> str:
    """Run an external command asynchronously and return stdout."""
    timeout = timeout or settings.SCAN_TIMEOUT
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
        if stderr and b"error" in stderr.lower():
            logger.warning("stderr from %s: %s", cmd[0], stderr.decode(errors="replace")[:500])
        return stdout.decode(errors="replace")
    except FileNotFoundError:
        logger.error("Tool not found: %s — is it installed?", cmd[0])
        return ""
    except asyncio.TimeoutError:
        logger.error("Command timed out after %ds: %s", timeout, " ".join(cmd))
        process.kill()
        return ""
    except Exception as exc:
        logger.error("Command failed (%s): %s", cmd[0], exc)
        return ""


async def _run_sslscan(host: str, port: int) -> Dict[str, Any]:
    target = f"{host}:{port}"
    logger.info("Running sslscan on %s...", target)
    output = await _run_command(["sslscan", "--no-colour", target])
    
    protocols = set()
    ciphers = []
    
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Accepted"):
            parts = line.split()
            if len(parts) >= 4:
                proto = parts[1]
                bits_raw = parts[2]
                cipher_name = parts[-1]
                protocols.add(proto)
                try:
                    bits = int(bits_raw)
                except ValueError:
                    bits = 0
                ciphers.append({"name": cipher_name, "protocol": proto, "bits": bits})
                
    return {"protocols": list(protocols), "ciphers": ciphers}


async def _run_testssl(host: str, port: int) -> Dict[str, Any]:
    target = f"{host}:{port}"
    temp_json = os.path.join(tempfile.gettempdir(), f"testssl_{uuid.uuid4().hex}.json")
    
    logger.info("Running testssl on %s...", target)
    cmd = ["testssl", "--fast", "--quiet", "--jsonfile", temp_json, target]
    await _run_command(cmd, timeout=300)
    
    results = []
    if os.path.exists(temp_json):
        try:
            with open(temp_json, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    results = data
        except Exception as e:
            logger.error("Failed to parse testssl JSON: %s", e)
        finally:
            try:
                os.remove(temp_json)
            except OSError:
                pass
                
    return _parse_testssl_json(results)


def _parse_testssl_json(data: List[Dict[str, Any]]) -> Dict[str, Any]:
    parsed = {
        "forward_secrecy": False,
        "cert_info": None,
        "cert_chain": [],
        "vulns": [],
        "protocols": set(),
        "ciphers": set()
    }
    cert = CertificateInfo()
    
    for item in data:
        id_val = item.get("id", "")
        finding = item.get("finding", "")
        
        if id_val == "forward_secrecy" and "supported" in finding.lower():
            parsed["forward_secrecy"] = True
        elif id_val == "cert_subject":
            cert.subject = finding
        elif id_val == "cert_issuer":
            cert.issuer = finding
        elif id_val == "cert_expiration":
            cert.not_after = finding
        elif id_val == "cert_signatureAlgorithm":
            cert.signature_algorithm = finding
        elif id_val == "cert_keySize":
            try:
                cert.public_key_size = int(finding.split()[0])
            except (ValueError, IndexError):
                pass
        elif id_val == "cert_chain_trust":
            is_valid = "ok" in finding.lower() or "trusted" in finding.lower()
            parsed["cert_chain"].append(CertChainEntry(depth=0, is_valid=is_valid, error=finding if not is_valid else None))
        elif id_val.startswith("TLS") or id_val.startswith("SSL"):
            # TestSSL protocol supported lines
            if "offered" in finding.lower():
                parsed["protocols"].add(id_val.replace("_", "."))
        elif id_val.startswith("cipher"):
            # We don't thoroughly extract all ciphers from testssl fast run right now, just noting the capacity
            pass
            
    if cert.subject and cert.issuer:
        cert.is_self_signed = cert.subject == cert.issuer
        
    if cert.not_after:
        try:
            m = re.search(r"(\d{4}-\d{2}-\d{2})", cert.not_after)
            if m:
                expiry = datetime.strptime(m.group(1), "%Y-%m-%d")
                cert.days_until_expiry = (expiry - datetime.utcnow()).days
        except Exception:
            pass
            
    parsed["cert_info"] = cert if cert.subject else None
    parsed["protocols"] = list(parsed["protocols"])
    return parsed


async def _run_zgrab2(host: str, port: int) -> bool:
    """Run zgrab2 tls to see if the host speaks TLS."""
    logger.info("Running ZGrab2 on %s:%d...", host, port)
    # create temporary input file for zgrab2
    temp_input = os.path.join(tempfile.gettempdir(), f"zgrab_{uuid.uuid4().hex}.txt")
    try:
        with open(temp_input, "w") as f:
            f.write(f"{host}\n")
        
        output = await _run_command(["zgrab2", "tls", "--port", str(port), "-f", temp_input])
        return '"status":"success"' in output
    finally:
        if os.path.exists(temp_input):
            try:
                os.remove(temp_input)
            except OSError:
                pass


async def _run_openssl(host: str, port: int) -> bool:
    """Run openssl s_client as a baseline validation."""
    logger.info("Running OpenSSL validation on %s:%d...", host, port)
    target = f"{host}:{port}"
    output = await _run_command(["sh", "-c", f"echo | openssl s_client -connect {target} 2>/dev/null"])
    return "CONNECTED" in output or "Cipher" in output


def _derive_key_exchange(cipher_name: str | None) -> str | None:
    if not cipher_name:
        return None
    name = cipher_name.upper().replace("-", "_")
    for token in ["ECDHE", "DHE", "ECDH", "DH", "RSA", "PSK"]:
        if token in name:
            return token
    return "UNKNOWN"


def _determine_confidence(sslscan_res: Dict, testssl_res: Dict, zgrab_success: bool, openssl_success: bool) -> ConfidenceLevel:
    """
    Multi-tool Validation Logic:
    Compare testssl.sh, sslscan, zgrab2, and openssl.
    """
    if not sslscan_res.get("protocols") and not testssl_res.get("cert_info"):
        return ConfidenceLevel.LOW
        
    # Baseline tools completely failed but advanced tools got something
    if not zgrab_success and not openssl_success:
        return ConfidenceLevel.LOW

    sslscan_protos = set(p.upper() for p in sslscan_res.get("protocols", []))
    testssl_protos = set(p.upper() for p in testssl_res.get("protocols", []))
    
    # testssl fast doesn't always populate protocols well depending on server.
    # We mainly compare what they *both* found.
    intersection = sslscan_protos.intersection(testssl_protos)
    union = sslscan_protos.union(testssl_protos)
    
    if testssl_protos and sslscan_protos:
        # If they disagree significantly
        if len(intersection) / len(union) < 0.5:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.HIGH

    # If only one tool returned protocols, we have medium confidence (no consensus)
    if sslscan_protos or testssl_protos:
        return ConfidenceLevel.MEDIUM
        
    return ConfidenceLevel.LOW


# Global semaphore to limit concurrent heavy tool executions per host.
# E.g., if Nmap finds 30 hosts, we don't want 30 parallel testssl.sh instances starving the CPU.
_scanner_semaphore = asyncio.Semaphore(5)

async def scan_tls(host: str, port: int) -> TLSInfo:
    """
    Execute external tools (sslscan, testssl.sh, zgrab2, openssl) and combine their results.
    """
    try:
        async with _scanner_semaphore:
            logger.info("External Multi-tool TLS scan on %s:%d (Semaphore Acquired)...", host, port)
            
            # Run all tools concurrently for THIS specific host
            results = await asyncio.gather(
                _run_sslscan(host, port),
                _run_testssl(host, port),
                _run_zgrab2(host, port),
                _run_openssl(host, port),
                return_exceptions=True
            )
        
        sslscan_res = results[0] if not isinstance(results[0], Exception) else {"protocols": [], "ciphers": []}
        testssl_res = results[1] if not isinstance(results[1], Exception) else {"cert_info": None, "forward_secrecy": False, "cert_chain": [], "protocols": []}
        zgrab_success = results[2] if not isinstance(results[2], Exception) else False
        openssl_success = results[3] if not isinstance(results[3], Exception) else False
    
        if not sslscan_res.get("ciphers") and not testssl_res.get("cert_info") and not openssl_success:
            return TLSInfo(host=host, port=port, error="All scanner tools failed or host does not speak TLS.")
    
        ciphers = sslscan_res.get("ciphers", [])
        protocols = sslscan_res.get("protocols", [])
        if not protocols and testssl_res.get("protocols"):
            protocols = testssl_res.get("protocols")
            
        tls_version = protocols[-1] if protocols else None
        
        cipher_suite = ciphers[0].get("name") if ciphers else None
        cipher_bits = ciphers[0].get("bits") if ciphers else None
        
        fs = testssl_res.get("forward_secrecy", False)
        if not fs and any(token in c.get("name", "").upper() for c in ciphers for token in ["ECDHE", "DHE", "ECDH"]):
            fs = True
    
        confidence = _determine_confidence(sslscan_res, testssl_res, zgrab_success, openssl_success)
    
        result = TLSInfo(
            host=host,
            port=port,
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            cipher_bits=cipher_bits,
            key_exchange=_derive_key_exchange(cipher_suite),
            certificate=testssl_res.get("cert_info"),
            all_supported_protocols=protocols,
            all_supported_ciphers=ciphers,
            supports_forward_secrecy=fs,
            cert_chain=testssl_res.get("cert_chain", []),
            confidence=confidence
        )
        
        logger.info(
            "TLS external scan complete for %s:%d — Conf: %s / %d ciphers / %d protocols",
            host, port, confidence.value, len(result.all_supported_ciphers), len(result.all_supported_protocols)
        )

        return enrich_tls_info(result)
    except Exception as exc:
        logger.error("Unhandled internal TLS scan exception on %s:%d : %s", host, port, exc, exc_info=True)
        return TLSInfo(host=host, port=port, error=f"Unhandled internal TLS scan exception: {str(exc)}")
