"""
intel/blocklist.py — IP blocklist management

Wraps cloud_db's blocklist_cache table + an in-memory fast-path.
Periodic AbuseIPDB refresh for IPs seen 2+ times.
"""

import asyncio
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import Optional

import httpx
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
REFRESH_INTERVAL = 300   # seconds between AbuseIPDB re-checks
ABUSE_THRESHOLD  = 50    # AbuseIPDB confidence score to auto-block

# ── In-memory fast-path ───────────────────────────────────────────────────────
# { ip: { "blocked": bool, "score": float, "source": str, "until": datetime } }
_cache: dict[str, dict] = {}
_lock  = Lock()

# Track how many times an IP has been seen (for AbuseIPDB refresh trigger)
_ip_seen_count: dict[str, int] = defaultdict(int)


# ── Core API ──────────────────────────────────────────────────────────────────

def is_blocklisted(ip: str) -> bool:
    """
    Returns True if IP is currently blocked.
    Checks in-memory cache first, then Supabase.
    """
    with _lock:
        entry = _cache.get(ip)
        if entry:
            if entry["until"] > datetime.now(timezone.utc):
                return entry["blocked"]
            else:
                # Expired — remove from cache
                del _cache[ip]

    # Supabase fallback
    try:
        from cloud_db import check_blocklist
        row = check_blocklist(ip)
        if row:
            # Warm the cache
            with _lock:
                _cache[ip] = {
                    "blocked": True,
                    "score":   row.get("score", 100),
                    "source":  row.get("source", "db"),
                    "until":   datetime.fromisoformat(row["blocked_until"]).replace(tzinfo=timezone.utc),
                }
            return True
    except Exception as e:
        logger.error("blocklist DB check failed for %s: %s", ip, e)

    return False


def add_to_blocklist(
    ip: str,
    source: str,
    score: float,
    hours: int = 24,
) -> None:
    """Add/update IP in both in-memory cache and Supabase."""
    until = datetime.now(timezone.utc) + timedelta(hours=hours)

    with _lock:
        _cache[ip] = {
            "blocked": True,
            "score":   score,
            "source":  source,
            "until":   until,
        }

    try:
        from cloud_db import add_to_blocklist as db_add
        db_add(ip, source, score, hours=hours)
        logger.info("IP %s added to blocklist (source=%s, score=%.0f).", ip, source, score)
    except Exception as e:
        logger.error("Failed to persist blocklist entry for %s: %s", ip, e)


def record_ip_seen(ip: str) -> None:
    """
    Track how many times an IP has been seen.
    Triggers an AbuseIPDB check when count reaches 2.
    """
    with _lock:
        _ip_seen_count[ip] += 1
        count = _ip_seen_count[ip]

    if count == 2 and ABUSEIPDB_KEY:
        # Schedule async check (fire-and-forget)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(_check_abuseipdb(ip))
        except RuntimeError:
            pass   # No event loop — skip (main.py context)


# ── AbuseIPDB integration ─────────────────────────────────────────────────────

async def _check_abuseipdb(ip: str) -> None:
    """Async AbuseIPDB check. Auto-blocks if confidence ≥ ABUSE_THRESHOLD."""
    if not ABUSEIPDB_KEY:
        return
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 30},
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            logger.info("AbuseIPDB: %s scored %d.", ip, score)

            if score >= ABUSE_THRESHOLD:
                add_to_blocklist(ip, source="abuseipdb", score=float(score))
    except Exception as e:
        logger.warning("AbuseIPDB check failed for %s: %s", ip, e)


async def periodic_blocklist_refresh() -> None:
    """
    Background loop: re-check AbuseIPDB for all IPs seen 2+ times.
    Runs every REFRESH_INTERVAL seconds.
    """
    while True:
        await asyncio.sleep(REFRESH_INTERVAL)
        if not ABUSEIPDB_KEY:
            continue
        with _lock:
            candidates = [ip for ip, c in _ip_seen_count.items() if c >= 2]
        for ip in candidates:
            await _check_abuseipdb(ip)
            await asyncio.sleep(0.5)   # rate-limit AbuseIPDB calls
