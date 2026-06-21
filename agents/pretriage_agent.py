"""
agents/pretriage_agent.py — Gemini-powered triage router

Polls agent_queue for receiver='pretriage_agent', status='PENDING'.
For each message:
  1. Builds a compact Gemini Flash prompt with alert context
  2. Parses reply → INVESTIGATE / RESPOND_DIRECTLY / LOG_ONLY
  3. Routes: updates queue receiver or closes out with audit log
  4. Wraps Gemini call with 5s timeout + 2 retries → default INVESTIGATE on failure
"""

import asyncio
import json
import logging
import os
import re

import google.genai as genai
from google.genai import types as genai_types
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

AGENT_NAME     = "pretriage_agent"
POLL_INTERVAL  = 3   # seconds between queue polls
GEMINI_MODEL   = "gemini-2.5-flash"
GEMINI_TIMEOUT = 10  # seconds per attempt
GEMINI_RETRIES = 2

_VALID_DECISIONS = {"INVESTIGATE", "RESPOND_DIRECTLY", "LOG_ONLY"}

_api_key = os.getenv("GEMINI_API_KEY", "")
_client  = genai.Client(api_key=_api_key) if _api_key else None
if not _api_key:
    logger.warning("GEMINI_API_KEY not set -- pretriage_agent will default to INVESTIGATE for all alerts.")


# ── Gemini call with timeout + retry ─────────────────────────────────────────

async def _call_gemini(prompt: str) -> str:
    """Call Gemini Flash with timeout + retries. Returns raw text or raises."""
    if not _client:
        raise RuntimeError("No Gemini API key")

    for attempt in range(GEMINI_RETRIES + 1):
        try:
            loop = asyncio.get_event_loop()
            resp = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: _client.models.generate_content(
                        model   = GEMINI_MODEL,
                        contents= prompt,
                    )
                ),
                timeout=GEMINI_TIMEOUT
            )
            return resp.text.strip()
        except asyncio.TimeoutError:
            logger.warning("Gemini timeout on attempt %d/%d", attempt + 1, GEMINI_RETRIES + 1)
        except Exception as e:
            logger.warning("Gemini error attempt %d: %s", attempt + 1, e)
        await asyncio.sleep(1)

    raise RuntimeError("All Gemini attempts failed")


def _parse_decision(text: str) -> str:
    """Extract decision keyword from Gemini response. Defaults to INVESTIGATE."""
    text_upper = text.upper()
    for decision in _VALID_DECISIONS:
        if decision in text_upper:
            return decision
    return "INVESTIGATE"


def _build_prompt(payload: dict) -> str:
    ip          = payload.get("ip", "unknown")
    attack_type = payload.get("attack_type", "unknown")
    rule_match  = payload.get("rule_match", "none")
    ml_score    = payload.get("ml_score", 0)
    verdict     = payload.get("verdict", "unknown")
    shap        = payload.get("shap_features", [])[:3]
    session     = payload.get("session_flags", {})
    url         = payload.get("url", "")[:120]

    shap_str = ", ".join(
        f"{f.get('feature')}={f.get('value')}" for f in shap
    ) if shap else "none"

    return f"""You are a SOC analyst triage agent. Classify this security alert and respond with EXACTLY ONE of:
INVESTIGATE / RESPOND_DIRECTLY / LOG_ONLY

Rules:
- RESPOND_DIRECTLY: high-confidence attack with strong rule+ML agreement, immediate action warranted
- INVESTIGATE: ambiguous signal, needs deeper enrichment (threat intel, WHOIS, MITRE mapping)
- LOG_ONLY: very low confidence, likely false positive or benign probe

Alert context:
  IP:           {ip}
  Attack type:  {attack_type}
  Rule match:   {rule_match}
  ML score:     {ml_score:.3f}
  Verdict:      {verdict}
  URL (trunc):  {url}
  SHAP features:{shap_str}
  Session flags: rapid_fire={session.get('is_rapid_fire')}, multi_vector={session.get('is_multi_vector')}, escalating={session.get('is_escalating')}

Respond with only the keyword (INVESTIGATE, RESPOND_DIRECTLY, or LOG_ONLY) on the first line, followed by one sentence of reasoning."""


# ── Main processing loop ──────────────────────────────────────────────────────

async def _process_message(msg: dict) -> None:
    from cloud_db import (
        update_queue_message, write_audit_log, update_agent_status
    )

    msg_id   = msg["id"]
    alert_id = msg.get("alert_id")
    payload  = msg.get("payload", {})

    update_agent_status(AGENT_NAME, "BUSY", alert_id)
    update_queue_message(msg_id, {"status": "PROCESSING"})

    # Try Gemini; default to INVESTIGATE on any failure (fail-safe)
    try:
        prompt   = _build_prompt(payload)
        raw_text = await _call_gemini(prompt)
        decision = _parse_decision(raw_text)
        reasoning = raw_text[:500]
        logger.info("[pretriage_agent] alert=%s decision=%s", alert_id, decision)
    except Exception as e:
        decision  = "INVESTIGATE"
        reasoning = f"Gemini unavailable ({e}) — defaulting to INVESTIGATE (fail-safe)."
        logger.warning("[pretriage_agent] %s", reasoning)

    # Route based on decision
    if decision == "LOG_ONLY":
        update_queue_message(msg_id, {"status": "DONE"})
        write_audit_log(
            agent     = AGENT_NAME,
            action    = "LOG_ONLY",
            reasoning = reasoning,
            metadata  = {"decision": decision},
            alert_id  = alert_id,
        )
    elif decision == "RESPOND_DIRECTLY":
        # Skip investigation — route straight to response
        from cloud_db import write_to_queue
        write_to_queue(
            sender   = AGENT_NAME,
            receiver = "response_agent",
            payload  = {**payload, "pretriage_decision": decision, "pretriage_reasoning": reasoning},
            alert_id = alert_id,
            priority = "HIGH",
        )
        update_queue_message(msg_id, {"status": "DONE"})
        write_audit_log(
            agent     = AGENT_NAME,
            action    = "ROUTE_TO_RESPONSE",
            reasoning = reasoning,
            metadata  = {"decision": decision},
            alert_id  = alert_id,
        )
    else:
        # INVESTIGATE — route to investigation agent
        from cloud_db import write_to_queue
        write_to_queue(
            sender   = AGENT_NAME,
            receiver = "investigation_agent",
            payload  = {**payload, "pretriage_decision": decision, "pretriage_reasoning": reasoning},
            alert_id = alert_id,
            priority = "MEDIUM",
        )
        update_queue_message(msg_id, {"status": "DONE"})
        write_audit_log(
            agent     = AGENT_NAME,
            action    = "ROUTE_TO_INVESTIGATION",
            reasoning = reasoning,
            metadata  = {"decision": decision},
            alert_id  = alert_id,
        )

    update_agent_status(AGENT_NAME, "IDLE")


async def run_forever() -> None:
    """Continuous poll loop. Start this as an asyncio task in run_agents.py."""
    from cloud_db import get_pending_queue_messages, update_agent_status
    update_agent_status(AGENT_NAME, "IDLE")
    logger.info("[pretriage_agent] started, polling every %ds.", POLL_INTERVAL)

    while True:
        try:
            messages = get_pending_queue_messages(AGENT_NAME, limit=5)
            for msg in messages:
                await _process_message(msg)
        except Exception as e:
            logger.error("[pretriage_agent] poll error: %s", e)

        await asyncio.sleep(POLL_INTERVAL)
