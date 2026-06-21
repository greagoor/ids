"""
intel/threat_enrichment.py — External threat intelligence enrichment

Wraps:
  - AbuseIPDB  (IP reputation)
  - VirusTotal (URL/IP lookup)
  - python-whois (domain registration info)

Each call has a hard timeout (5-8s) and returns None on any failure,
so investigation_agent never hangs on a slow external service.
"""

import asyncio
import logging
import os
from typing import Optional

import httpx
import whois
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
HTTP_TIMEOUT    = 7.0   # seconds


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

async def check_abuseipdb(ip: str) -> Optional[dict]:
    """
    Returns AbuseIPDB reputation data for an IP, or None on failure.
    """
    if not ABUSEIPDB_KEY:
        logger.debug("ABUSEIPDB_API_KEY not set — skipping.")
        return None
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={
                    "ipAddress":    ip,
                    "maxAgeInDays": 30,
                    "verbose":      True,
                },
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "source":             "abuseipdb",
                "abuse_confidence":   data.get("abuseConfidenceScore", 0),
                "country":            data.get("countryCode"),
                "usage_type":         data.get("usageType"),
                "isp":                data.get("isp"),
                "total_reports":      data.get("totalReports", 0),
                "last_reported":      data.get("lastReportedAt"),
                "is_tor":             data.get("isTor", False),
            }
    except Exception as e:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
        return None


# ── VirusTotal ────────────────────────────────────────────────────────────────

async def check_virustotal_ip(ip: str) -> Optional[dict]:
    """
    Returns VirusTotal reputation for an IP, or None on failure.
    """
    if not VIRUSTOTAL_KEY:
        logger.debug("VIRUSTOTAL_API_KEY not set — skipping.")
        return None
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
            )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source":      "virustotal",
                "malicious":   stats.get("malicious", 0),
                "suspicious":  stats.get("suspicious", 0),
                "harmless":    stats.get("harmless", 0),
                "country":     attrs.get("country"),
                "asn":         attrs.get("asn"),
                "as_owner":    attrs.get("as_owner"),
                "reputation":  attrs.get("reputation", 0),
            }
    except Exception as e:
        logger.warning("VirusTotal IP lookup failed for %s: %s", ip, e)
        return None


async def check_virustotal_url(url: str) -> Optional[dict]:
    """
    Returns VirusTotal reputation for a URL (via URL identifier), or None.
    """
    if not VIRUSTOTAL_KEY:
        return None
    import base64
    try:
        # VT v3 URL lookup requires base64url-encoded URL (no padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
            )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source":     "virustotal_url",
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "categories": attrs.get("categories", {}),
            }
    except Exception as e:
        logger.warning("VirusTotal URL lookup failed: %s", e)
        return None


# ── WHOIS ─────────────────────────────────────────────────────────────────────

async def check_whois(domain: str) -> Optional[dict]:
    """
    Returns WHOIS registration info for a domain, or None on failure.
    Runs python-whois in a thread executor (it's synchronous).
    """
    try:
        loop = asyncio.get_event_loop()
        w = await asyncio.wait_for(
            loop.run_in_executor(None, whois.whois, domain),
            timeout=8.0
        )
        return {
            "source":       "whois",
            "registrar":    w.registrar if hasattr(w, "registrar") else None,
            "creation_date": str(w.creation_date) if hasattr(w, "creation_date") else None,
            "expiration_date": str(w.expiration_date) if hasattr(w, "expiration_date") else None,
            "country":      w.country if hasattr(w, "country") else None,
            "name_servers": w.name_servers if hasattr(w, "name_servers") else [],
        }
    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)
        return None


# ── Bundled enrichment helper ─────────────────────────────────────────────────

async def enrich_ip(ip: str) -> dict:
    """
    Run all enrichment checks concurrently for an IP.
    Returns a dict with keys 'abuseipdb', 'virustotal', each None if failed.
    """
    abuse_task = asyncio.create_task(check_abuseipdb(ip))
    vt_task    = asyncio.create_task(check_virustotal_ip(ip))
    abuse, vt  = await asyncio.gather(abuse_task, vt_task, return_exceptions=True)

    return {
        "abuseipdb":  abuse if isinstance(abuse, dict) else None,
        "virustotal": vt    if isinstance(vt, dict)    else None,
    }
