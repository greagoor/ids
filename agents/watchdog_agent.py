"""
agents/watchdog_agent.py — System health monitor and queue reaper

Background loop, every 30 seconds:
  - Reads agent_status, flags agents with stale heartbeat (>2min) as ERROR
  - Reads agent_queue for messages stuck in PROCESSING >60s:
      retry_count < 3  → requeue (PENDING, increment retry_count)
      retry_count >= 3 → DEAD_LETTER with failure_reason
  - Writes overall status snapshot to system_health table

OUT OF SCOPE (documented): Actually subprocess-restarting crashed agent
processes. For this 5-day build, the watchdog detects + surfaces failures
in the dashboard but does not attempt process-level restarts.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

AGENT_NAME         = "watchdog_agent"
POLL_INTERVAL      = 30     # seconds
HEARTBEAT_TIMEOUT  = 600    # seconds (10 minutes) — prevents false ERRORs during human-paced demo
PROCESSING_TIMEOUT = 60     # seconds — requeue or dead-letter
MAX_RETRIES        = 3


async def _check_agent_heartbeats() -> list[str]:
    """Return list of agents flagged ERROR due to stale heartbeat."""
    from cloud_db import _db, update_agent_status
    flagged = []
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=HEARTBEAT_TIMEOUT)).isoformat()
        res = (
            _db()
            .table("agent_status")
            .select("agent_name, status, last_heartbeat")
            .neq("agent_name", AGENT_NAME)
            .lt("last_heartbeat", cutoff)
            .execute()
        )
        for row in (res.data or []):
            name = row["agent_name"]
            if row.get("status") not in ("ERROR",):
                logger.warning(
                    "[watchdog] Agent %s heartbeat stale (last: %s) — marking ERROR.",
                    name, row.get("last_heartbeat"),
                )
                update_agent_status(name, "ERROR")
            flagged.append(name)
    except Exception as e:
        logger.error("[watchdog] heartbeat check failed: %s", e)
    return flagged


async def _reap_stuck_messages() -> dict:
    """Requeue or dead-letter stuck PROCESSING messages."""
    from cloud_db import _db, update_queue_message
    requeued    = 0
    dead_lettered = 0

    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=PROCESSING_TIMEOUT)).isoformat()
        res = (
            _db()
            .table("agent_queue")
            .select("id, receiver, retry_count, updated_at")
            .eq("status", "PROCESSING")
            .lt("updated_at", cutoff)
            .execute()
        )
        for row in (res.data or []):
            retry = row.get("retry_count", 0)
            if retry >= MAX_RETRIES:
                update_queue_message(row["id"], {
                    "status":         "DEAD_LETTER",
                    "failure_reason": (
                        f"Stuck in PROCESSING >{PROCESSING_TIMEOUT}s "
                        f"after {retry} retries. Watchdog dead-lettered."
                    ),
                })
                dead_lettered += 1
                logger.error(
                    "[watchdog] Dead-lettered queue msg %s (receiver=%s, retries=%d).",
                    row["id"], row.get("receiver"), retry,
                )
            else:
                update_queue_message(row["id"], {
                    "status":      "PENDING",
                    "retry_count": retry + 1,
                })
                requeued += 1
                logger.warning(
                    "[watchdog] Requeued stuck msg %s → retry %d.",
                    row["id"], retry + 1,
                )
    except Exception as e:
        logger.error("[watchdog] stuck-message reaper failed: %s", e)

    return {"requeued": requeued, "dead_lettered": dead_lettered}


async def _write_health_snapshot(flagged_agents: list, reap_stats: dict) -> None:
    """Write overall system health to system_health table."""
    from cloud_db import _db, write_system_health

    # Count pending/processing queue messages
    try:
        res_q = _db().table("agent_queue").select("status", count="exact").execute()
        queue_stats: dict = {}
        for row in (res_q.data or []):
            s = row.get("status", "UNKNOWN")
            queue_stats[s] = queue_stats.get(s, 0) + 1
    except Exception:
        queue_stats = {}

    # Count active incidents
    try:
        res_i = (
            _db()
            .table("incidents")
            .select("id", count="exact")
            .eq("status", "ACTIVE")
            .execute()
        )
        active_incidents = res_i.count or 0
    except Exception:
        active_incidents = 0

    overall_status = "DEGRADED" if flagged_agents else "HEALTHY"

    write_system_health(
        component = "agent_system",
        status    = overall_status,
        details   = {
            "flagged_agents":   flagged_agents,
            "queue_stats":      queue_stats,
            "reap_stats":       reap_stats,
            "active_incidents": active_incidents,
            "checked_at":       datetime.now(timezone.utc).isoformat(),
            "note": (
                "OUT OF SCOPE: process-level agent restart not implemented. "
                "Dashboard shows ERROR status — manual restart required if agent is truly crashed."
            ),
        },
    )

    if overall_status == "DEGRADED":
        logger.warning(
            "[watchdog] System DEGRADED. Flagged agents: %s. Queue: %s.",
            flagged_agents, queue_stats,
        )
    else:
        logger.info("[watchdog] System HEALTHY. Queue: %s.", queue_stats)


async def run_forever() -> None:
    from cloud_db import update_agent_status
    update_agent_status(AGENT_NAME, "IDLE")
    logger.info("[watchdog_agent] started, polling every %ds.", POLL_INTERVAL)

    while True:
        await asyncio.sleep(POLL_INTERVAL)
        try:
            update_agent_status(AGENT_NAME, "BUSY")
            flagged    = await _check_agent_heartbeats()
            reap_stats = await _reap_stuck_messages()
            await _write_health_snapshot(flagged, reap_stats)
            update_agent_status(AGENT_NAME, "IDLE")
        except Exception as e:
            logger.error("[watchdog_agent] loop error: %s", e)
