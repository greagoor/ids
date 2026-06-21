"""
core/session_tracker.py — Sliding-window per-IP behavioral tracker

Primary store: in-memory dict (fast, zero latency).
Durability: async write-through to `session_activity` Supabase table.

On startup: reloads sessions from the last 10 minutes from Supabase,
logging a visible warning with the recovered count so silent state loss
after a crash/restart is never possible.

Tracks per IP:
  - requests/min
  - unique endpoints hit
  - error response ratio
  - repeated parameter usage
  - session age
  - escalation_score (rolling suspicion accumulation)
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import Optional

logger = logging.getLogger(__name__)

# ── In-memory session store ───────────────────────────────────────────────────
# Structure per IP:
# {
#   "window_start":    float (epoch),
#   "req_timestamps":  deque of float epochs (last 60s window),
#   "endpoints_hit":   set of str,
#   "attack_types":    list of str,
#   "error_count":     int,
#   "total_count":     int,
#   "param_usage":     dict { param_name: count },
#   "escalation_score": float,
# }

_sessions: dict = {}
_lock = Lock()

WINDOW_SECONDS = 60        # sliding window for req/min calc
ESCALATION_DECAY = 0.95    # decay per minute when no new attacks seen
WRITE_INTERVAL  = 30       # seconds between write-through flushes


# ── Startup: reload from Supabase ────────────────────────────────────────────

def _reload_from_db() -> None:
    """
    On startup, pull sessions updated in the last 10 minutes from Supabase
    and restore them into the in-memory store.
    Logs clearly so silent state loss is never invisible.
    """
    try:
        from cloud_db import get_recent_sessions_from_db  # late import to avoid circular
        rows = get_recent_sessions_from_db(minutes=10)
        count = 0
        with _lock:
            for row in rows:
                ip = row.get("ip")
                if not ip:
                    continue
                _sessions[ip] = {
                    "window_start":     time.time(),
                    "req_timestamps":   deque(maxlen=500),
                    "endpoints_hit":    set(row.get("endpoints_hit") or []),
                    "attack_types":     list(row.get("attack_types") or []),
                    "error_count":      0,
                    "total_count":      row.get("req_count", 0),
                    "param_usage":      {},
                    "escalation_score": float(row.get("escalation_score") or 0.0),
                }
                count += 1

        if count > 0:
            logger.warning(
                "SESSION TRACKER: Recovered %d sessions from Supabase "
                "(last 10 min). State continuity preserved after restart.",
                count
            )
        else:
            logger.info(
                "SESSION TRACKER: No recent sessions found in Supabase. "
                "Starting with empty in-memory store."
            )
    except Exception as e:
        logger.error(
            "SESSION TRACKER: Failed to reload sessions from Supabase: %s. "
            "Starting empty — some escalation context may be lost.",
            e
        )


# ── Core tracker functions ────────────────────────────────────────────────────

def record_request(
    ip: str,
    endpoint: str,
    response_code: str,
    params: Optional[dict] = None,
    attack_type: Optional[str] = None,
    suspicion_score: float = 0.0,
) -> None:
    """
    Record a single request from an IP. Thread-safe.
    Call this after detection logic for accurate escalation scoring.
    """
    now = time.time()

    with _lock:
        if ip not in _sessions:
            _sessions[ip] = {
                "window_start":     now,
                "req_timestamps":   deque(maxlen=500),
                "endpoints_hit":    set(),
                "attack_types":     [],
                "error_count":      0,
                "total_count":      0,
                "param_usage":      defaultdict(int),
                "escalation_score": 0.0,
            }

        sess = _sessions[ip]
        sess["req_timestamps"].append(now)
        sess["endpoints_hit"].add(endpoint)
        sess["total_count"] += 1

        if response_code.startswith(("4", "5")):
            sess["error_count"] += 1

        if params:
            for k in params:
                sess["param_usage"][k] = sess["param_usage"].get(k, 0) + 1

        if attack_type and attack_type not in ("NORMAL", "BENIGN", None):
            sess["attack_types"].append(attack_type)

        # Accumulate escalation score (suspicion_score is 0-1)
        if suspicion_score > 0:
            sess["escalation_score"] = min(
                100.0,
                sess["escalation_score"] + suspicion_score * 20
            )


def get_session_flags(ip: str) -> dict:
    """
    Return behavioural flags for an IP.
    Returns empty/safe defaults if no session exists.
    """
    now = time.time()
    with _lock:
        if ip not in _sessions:
            return _default_flags()

        sess = _sessions[ip]

        # Prune old timestamps outside sliding window
        cutoff = now - WINDOW_SECONDS
        while sess["req_timestamps"] and sess["req_timestamps"][0] < cutoff:
            sess["req_timestamps"].popleft()

        req_per_min = len(sess["req_timestamps"])
        total       = max(sess["total_count"], 1)
        error_ratio = sess["error_count"] / total
        session_age_s = now - sess["window_start"]

        # Repeated param detection: any param used >3 times
        repeated_params = [
            k for k, v in sess.get("param_usage", {}).items() if v > 3
        ]

        return {
            "ip":                ip,
            "req_per_min":       req_per_min,
            "unique_endpoints":  len(sess["endpoints_hit"]),
            "error_ratio":       round(error_ratio, 3),
            "repeated_params":   repeated_params,
            "session_age_s":     round(session_age_s, 1),
            "attack_types_seen": list(set(sess["attack_types"])),
            "escalation_score":  round(sess["escalation_score"], 2),
            # Derived flags
            "is_rapid_fire":     req_per_min > 30,
            "is_error_heavy":    error_ratio > 0.5,
            "is_multi_vector":   len(set(sess["attack_types"])) > 1,
            "is_escalating":     sess["escalation_score"] > 50,
        }


def _default_flags() -> dict:
    return {
        "ip": "",
        "req_per_min": 0,
        "unique_endpoints": 0,
        "error_ratio": 0.0,
        "repeated_params": [],
        "session_age_s": 0.0,
        "attack_types_seen": [],
        "escalation_score": 0.0,
        "is_rapid_fire": False,
        "is_error_heavy": False,
        "is_multi_vector": False,
        "is_escalating": False,
    }


def increment_escalation(ip: str, delta: float) -> None:
    """Directly add to escalation score for an IP (e.g. from response_agent)."""
    with _lock:
        if ip in _sessions:
            _sessions[ip]["escalation_score"] = min(
                100.0,
                _sessions[ip]["escalation_score"] + delta
            )


def reset_session(ip: str) -> None:
    """Clear session data for an IP (e.g. after a block)."""
    with _lock:
        _sessions.pop(ip, None)


def get_all_sessions() -> dict:
    """Return a snapshot of all in-memory sessions (for watchdog/healthcheck)."""
    with _lock:
        return {ip: dict(sess) for ip, sess in _sessions.items()}


# ── Async write-through flush ─────────────────────────────────────────────────

async def _flush_to_db() -> None:
    """
    Periodically writes in-memory sessions to Supabase session_activity table.
    Non-blocking — runs as an asyncio background task.
    """
    from cloud_db import upsert_session  # late import

    while True:
        await asyncio.sleep(WRITE_INTERVAL)
        try:
            with _lock:
                snapshot = {ip: dict(sess) for ip, sess in _sessions.items()}

            for ip, sess in snapshot.items():
                data = {
                    "req_count":        sess["total_count"],
                    "endpoints_hit":    list(sess.get("endpoints_hit", [])),
                    "attack_types":     list(set(sess.get("attack_types", []))),
                    "escalation_score": sess.get("escalation_score", 0.0),
                }
                upsert_session(ip, data)
        except Exception as e:
            logger.error("Session flush to DB failed: %s", e)


async def start_background_flush() -> None:
    """Start the DB write-through loop as an asyncio task."""
    asyncio.create_task(_flush_to_db())
    logger.info("Session tracker write-through flush started (every %ds).", WRITE_INTERVAL)


# ── Module init: reload on import ────────────────────────────────────────────
_reload_from_db()
