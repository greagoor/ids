"""
agents/honeypot_agent.py — Background processor for honeypot-triggered alerts

Polls agent_queue for honeypot-sourced alerts and runs them through
the full investigation chain. Lightweight wrapper — the heavy lifting is
already done by detection_agent when it's called from honeypot.py.
This agent primarily ensures honeypot alerts get MITRE-enriched + investigated.
"""

import asyncio
import logging

logger = logging.getLogger(__name__)

AGENT_NAME    = "honeypot_agent"
POLL_INTERVAL = 5   # seconds


async def run_forever() -> None:
    from cloud_db import (
        get_pending_queue_messages, update_agent_status,
        update_queue_message, write_audit_log, write_to_queue
    )
    update_agent_status(AGENT_NAME, "IDLE")
    logger.info("[honeypot_agent] started.")

    while True:
        try:
            # Pick up alerts specifically routed to honeypot_agent
            messages = get_pending_queue_messages(AGENT_NAME, limit=3)
            for msg in messages:
                payload = msg.get("payload", {})

                alert_id = msg.get("alert_id")
                update_agent_status(AGENT_NAME, "BUSY", alert_id)
                update_queue_message(msg["id"], {"status": "PROCESSING"})

                # Honeypot hits are high-confidence — route directly to investigation
                write_to_queue(
                    sender   = AGENT_NAME,
                    receiver = "investigation_agent",
                    payload  = {
                        **payload,
                        "pretriage_decision": "INVESTIGATE",
                        "pretriage_reasoning": "Honeypot endpoint hit — auto-routed to investigation.",
                    },
                    alert_id = alert_id,
                    priority = "HIGH",
                )

                write_audit_log(
                    agent     = AGENT_NAME,
                    action    = "HONEYPOT_ROUTED",
                    reasoning = f"Honeypot hit from {payload.get('ip','?')} on {payload.get('url','?')} — routed to investigation.",
                    metadata  = {"source": "honeypot", "ip": payload.get("ip")},
                    alert_id  = alert_id,
                )

                update_queue_message(msg["id"], {"status": "DONE"})
                update_agent_status(AGENT_NAME, "IDLE")

        except Exception as e:
            logger.error("[honeypot_agent] loop error: %s", e)

        await asyncio.sleep(POLL_INTERVAL)
