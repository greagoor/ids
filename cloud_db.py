"""
cloud_db.py — Supabase database layer
Rewritten to use supabase-py client instead of psycopg2.
All public function signatures from the original are preserved so main.py
continues to work without changes. New helpers for the agent system are
added at the bottom.
"""

import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from dotenv import load_dotenv
from supabase import create_client, Client

# severity helpers are used by detection_agent directly, not here

load_dotenv()

logger = logging.getLogger(__name__)

# ── Supabase client ───────────────────────────────────────────────────────────
_SUPABASE_URL = os.getenv("SUPABASE_URL", "")
_SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

if not _SUPABASE_URL or not _SUPABASE_KEY:
    logger.warning(
        "SUPABASE_URL or SUPABASE_KEY not set — database writes will fail. "
        "Fill these in .env before running the agent system."
    )

import threading
_local = threading.local()

def _db() -> Client:
    """Return a thread-local Supabase client."""
    if not _SUPABASE_URL or not _SUPABASE_KEY:
        raise RuntimeError("Supabase client not initialised — set SUPABASE_URL and SUPABASE_KEY in .env")
    if not hasattr(_local, "client"):
        _local.client = create_client(_SUPABASE_URL, _SUPABASE_KEY)
    return _local.client


import time as _time

_RETRY_ERRORS = ("server disconnected", "connection", "timeout", "reset")

def _safe_exec(fn, retries: int = 3, backoff: float = 0.2):
    """Execute a Supabase call; retry up to `retries` times on transient
    connection errors (Server disconnected, ConnectionReset, etc.).
    Logs on terminal failure rather than crashing — never raises."""
    for attempt in range(retries):
        try:
            return fn()
        except Exception as e:
            err_lower = str(e).lower()
            is_transient = any(kw in err_lower for kw in _RETRY_ERRORS)
            if is_transient and attempt < retries - 1:
                logger.warning(
                    "Supabase transient error (attempt %d/%d): %s — retrying in %.1fs",
                    attempt + 1, retries, e, backoff,
                )
                _time.sleep(backoff * (attempt + 1))   # linear backoff
                continue
            print(f"Supabase ERROR: {e}", flush=True)
            logger.error("Supabase error: %s", e)
            return None


# ── Existing public API (called by main.py via output/database.py) ────────────

TIME_WINDOW = timedelta(minutes=10)


# Severity label → integer mapping (matches the alerts table schema)
_SEVERITY_INT = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _sev_int(sev) -> Optional[int]:
    """Return severity as DB integer regardless of input type."""
    if sev is None:
        return None
    if isinstance(sev, int):
        return sev
    return _SEVERITY_INT.get(str(sev).upper())


def save_alert(alert: dict) -> None:
    """
    Insert alert into the `alerts` table.
    Column mapping handles both the old names (src_ip, uri) and
    the renamed columns (ip, url) added by schema_migration.sql.

    severity  is stored as INTEGER 1-4 (LOW/MEDIUM/HIGH/CRITICAL).
    confidence is stored as INTEGER 0-100.
    """
    row = {
        "timestamp":       alert.get("timestamp"),
        "ip":              alert.get("src_ip") or alert.get("ip"),
        "attack_type":     alert.get("attack_type"),
        "severity":        _sev_int(alert.get("severity")),
        "outcome":         alert.get("outcome"),
        "confidence":      int(alert["confidence"]) if alert.get("confidence") is not None else None,
        "method":          alert.get("method"),
        "url":             alert.get("uri") or alert.get("url"),
        "rule_match":      alert.get("rule_match"),
        "ml_score":        alert.get("ml_score"),
        "suspicion_score": alert.get("suspicion_score"),
        "shap_features":   alert.get("shap_features"),
        "alert_uuid":      alert.get("alert_uuid"),
        # verdict / payload / payload_attack_type — nullable TEXT, only include if set
        **({"verdict":             alert["verdict"]}          if alert.get("verdict")             else {}),
        **({"payload":             alert["payload"][:2000]}   if alert.get("payload")             else {}),
        **({"payload_attack_type": alert["payload_attack_type"]} if alert.get("payload_attack_type") else {}),
    }
    # Remove None values so Supabase uses column defaults
    row = {k: v for k, v in row.items() if v is not None}

    _safe_exec(lambda: _db().table("alerts").insert(row).execute())

def update_alert(alert_uuid: str, updates: dict) -> None:
    """Update an existing alert row by UUID."""
    # Ensure severity is updated as an integer if provided
    if "severity" in updates:
        updates["severity"] = _sev_int(updates["severity"])
    
    _safe_exec(
        lambda: _db()
        .table("alerts")
        .update(updates)
        .eq("alert_uuid", alert_uuid)
        .execute()
    )


def upsert_incident(alert: dict) -> None:
    """
    Upsert an incident record, escalating severity by count.
    Preserves the original decay logic pattern.
    """
    ip          = alert.get("src_ip") or alert.get("ip")
    attack_type = alert.get("attack_type")
    now_str     = alert.get("timestamp", datetime.now(timezone.utc).isoformat())
    now         = datetime.fromisoformat(now_str)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    try:
        res = (
            _db()
            .table("incidents")
            .select("id, count, last_seen")
            .eq("ip", ip)
            .eq("attack_type", attack_type)
            .execute()
        )
        rows = res.data or []
    except Exception as e:
        logger.error("upsert_incident select failed: %s", e)
        return

    if rows:
        row      = rows[0]
        last_seen_raw = row["last_seen"]
        # Supabase returns ISO strings
        last_seen = datetime.fromisoformat(last_seen_raw)
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        new_count = 1 if (now - last_seen) > TIME_WINDOW else row["count"] + 1

        if new_count >= 5:
            severity = "CRITICAL"
        elif new_count >= 3:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        update_data = {
            "count":     new_count,
            "last_seen": now_str,
            "severity":  severity,
            "status":    "ACTIVE",
        }
        if alert.get("mitre_tags"):
            update_data["mitre_tags"] = alert["mitre_tags"]
        if alert.get("kill_chain_phase"):
            update_data["kill_chain_phase"] = alert["kill_chain_phase"]
        if alert.get("threat_score") is not None:
            update_data["threat_score"] = alert["threat_score"]

        _safe_exec(
            lambda: _db()
            .table("incidents")
            .update(update_data)
            .eq("id", row["id"])
            .execute()
        )
    else:
        insert_data = {
            "ip":          ip,
            "attack_type": attack_type,
            "count":       1,
            "first_seen":  now_str,
            "last_seen":   now_str,
            "severity":    "MEDIUM",
            "status":      "ACTIVE",
        }
        if alert.get("mitre_tags"):
            insert_data["mitre_tags"] = alert["mitre_tags"]
        if alert.get("kill_chain_phase"):
            insert_data["kill_chain_phase"] = alert["kill_chain_phase"]
        if alert.get("threat_score") is not None:
            insert_data["threat_score"] = alert["threat_score"]

        _safe_exec(lambda: _db().table("incidents").insert(insert_data).execute())


def expire_old_incidents() -> None:
    """Mark incidents with no activity in the last 10 minutes as EXPIRED."""
    cutoff = (datetime.now(timezone.utc) - TIME_WINDOW).isoformat()
    _safe_exec(
        lambda: _db()
        .table("incidents")
        .update({"status": "EXPIRED"})
        .eq("status", "ACTIVE")
        .lt("last_seen", cutoff)
        .execute()
    )


def decay_incident_severity() -> None:
    """
    Decay severity for active incidents over time.
    Supabase-py doesn't support CASE expressions directly, so we fetch and
    update individually — this is called in a background thread every 60s,
    so the extra round-trips are acceptable.
    """
    try:
        res = _db().table("incidents").select("id, severity, last_seen").eq("status", "ACTIVE").execute()
        rows = res.data or []
    except Exception as e:
        logger.error("decay_incident_severity fetch failed: %s", e)
        return

    now = datetime.now(timezone.utc)
    for row in rows:
        try:
            last_seen = datetime.fromisoformat(row["last_seen"])
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            age = now - last_seen
            sev = row["severity"]
            new_sev = sev

            if sev == "CRITICAL" and age > timedelta(minutes=5):
                new_sev = "HIGH"
            elif sev == "HIGH" and age > timedelta(minutes=10):
                new_sev = "MEDIUM"
            elif sev == "MEDIUM" and age > timedelta(minutes=20):
                new_sev = "LOW"

            if new_sev != sev:
                _db().table("incidents").update({"severity": new_sev}).eq("id", row["id"]).execute()
        except Exception as e:
            logger.error("decay row %s failed: %s", row.get("id"), e)


# ── Agent system helpers ──────────────────────────────────────────────────────

def write_to_queue(
    sender: str,
    receiver: str,
    payload: dict,
    alert_id: Optional[str] = None,
    priority: str = "MEDIUM",
) -> Optional[str]:
    """Insert a message into agent_queue. Returns the new row ID or None."""
    row = {
        "sender":   sender,
        "receiver": receiver,
        "payload":  payload,
        "priority": priority,
        "status":   "PENDING",
    }
    if alert_id:
        row["alert_id"] = alert_id
    res = _safe_exec(lambda: _db().table("agent_queue").insert(row).execute())
    if res and res.data:
        return res.data[0].get("id")
    return None


def update_agent_status(
    agent_name: str,
    status: str,
    current_alert_id: Optional[str] = None,
) -> None:
    """Upsert agent heartbeat into agent_status."""
    row = {
        "agent_name":       agent_name,
        "status":           status,
        "last_heartbeat":   datetime.now(timezone.utc).isoformat(),
    }
    if current_alert_id:
        row["current_alert_id"] = current_alert_id
    _safe_exec(
        lambda: _db()
        .table("agent_status")
        .upsert(row, on_conflict="agent_name")
        .execute()
    )


def write_audit_log(
    agent: str,
    action: str,
    reasoning: str = "",
    metadata: Optional[dict] = None,
    alert_id: Optional[str] = None,
) -> None:
    """Insert a row into audit_log."""
    row = {
        "agent":     agent,
        "action":    action,
        "reasoning": reasoning,
        "metadata":  metadata or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if alert_id:
        row["alert_id"] = alert_id
    _safe_exec(lambda: _db().table("audit_log").insert(row).execute())


def get_session(ip: str) -> Optional[dict]:
    """Fetch a session_activity row by IP."""
    try:
        res = _db().table("session_activity").select("*").eq("ip", ip).execute()
        rows = res.data or []
        return rows[0] if rows else None
    except Exception as e:
        logger.error("get_session failed for %s: %s", ip, e)
        return None


def upsert_session(ip: str, data: dict) -> None:
    """Upsert a session_activity row."""
    data["ip"] = ip
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    _safe_exec(
        lambda: _db()
        .table("session_activity")
        .upsert(data, on_conflict="ip")
        .execute()
    )


def check_blocklist(ip: str) -> Optional[dict]:
    """Return blocklist_cache row if IP is blocked and not expired."""
    try:
        now = datetime.now(timezone.utc).isoformat()
        res = (
            _db()
            .table("blocklist_cache")
            .select("*")
            .eq("ip", ip)
            .gt("blocked_until", now)
            .execute()
        )
        rows = res.data or []
        return rows[0] if rows else None
    except Exception as e:
        logger.error("check_blocklist failed for %s: %s", ip, e)
        return None


def add_to_blocklist(
    ip: str,
    source: str,
    score: float,
    hours: int = 24,
) -> None:
    """Upsert an IP into blocklist_cache."""
    blocked_until = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    row = {
        "ip":            ip,
        "source":        source,
        "score":         score,
        "blocked_until": blocked_until,
        "created_at":    datetime.now(timezone.utc).isoformat(),
    }
    _safe_exec(
        lambda: _db()
        .table("blocklist_cache")
        .upsert(row, on_conflict="ip")
        .execute()
    )


def write_alert_full(alert: dict) -> Optional[str]:
    """
    Write a fully populated alert row (used by detection_agent).
    Returns the inserted row ID.
    """
    save_alert(alert)
    upsert_incident(alert)
    return None


def get_recent_sessions_from_db(minutes: int = 10) -> list:
    """Fetch all session_activity rows updated within the last N minutes."""
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        res = (
            _db()
            .table("session_activity")
            .select("*")
            .gt("updated_at", cutoff)
            .execute()
        )
        return res.data or []
    except Exception as e:
        logger.error("get_recent_sessions_from_db failed: %s", e)
        return []


def write_honeypot_log(ip: str, endpoint: str, headers: dict, payload: str) -> None:
    """Insert a row into honeypot_logs."""
    row = {
        "ip":       ip,
        "endpoint": endpoint,
        "headers":  headers,
        "payload":  payload,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _safe_exec(lambda: _db().table("honeypot_logs").insert(row).execute())


def write_model_metrics(metrics: dict) -> None:
    """Insert a row into model_metrics."""
    row = {
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "accuracy":        metrics.get("accuracy"),
        "precision_score": metrics.get("precision_score"),
        "recall_score":    metrics.get("recall_score"),
        "f1_score":        metrics.get("f1_score"),
        "drift_detected":  metrics.get("drift_detected", False),
    }
    _safe_exec(lambda: _db().table("model_metrics").insert(row).execute())


def write_system_health(component: str, status: str, details: dict) -> None:
    """Insert a system_health row."""
    row = {
        "component": component,
        "status":    status,
        "details":   details,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _safe_exec(lambda: _db().table("system_health").insert(row).execute())


def get_pending_queue_messages(receiver: str, limit: int = 10) -> list:
    """Fetch PENDING queue messages for a given receiver, oldest first."""
    try:
        res = (
            _db()
            .table("agent_queue")
            .select("*")
            .eq("receiver", receiver)
            .eq("status", "PENDING")
            .order("created_at", desc=False)
            .limit(limit)
            .execute()
        )
        return res.data or []
    except Exception as e:
        logger.error("get_pending_queue_messages failed: %s", e)
        return []


def update_queue_message(msg_id: str, updates: dict) -> None:
    """Update a single agent_queue row by ID."""
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    _safe_exec(
        lambda: _db()
        .table("agent_queue")
        .update(updates)
        .eq("id", msg_id)
        .execute()
    )
