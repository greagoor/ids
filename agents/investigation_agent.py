"""
agents/investigation_agent.py — Deep threat investigation with Gemini + intel tools

Polls agent_queue for receiver='investigation_agent'.
For each message:
  1. Runs all intel tools via call_tool_safe() circuit breaker
  2. Compiles evidence (skipping None results)
  3. Sends to Gemini → strict JSON verdict
  4. Writes full report to audit_log
  5. Routes to response_agent
  6. Dead-letters after 60s processing timeout or retry_count >= 3
"""

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone, timedelta
from typing import Optional

import google.genai as genai
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

AGENT_NAME      = "investigation_agent"
POLL_INTERVAL   = 4   # seconds
GEMINI_MODEL    = "gemini-2.5-flash"
PROCESSING_TIMEOUT = 60
MAX_RETRIES     = 3

_api_key = os.getenv("GEMINI_API_KEY", "")
_client  = genai.Client(api_key=_api_key) if _api_key else None


# ── Circuit-breaker tool wrapper ──────────────────────────────────────────────

async def call_tool_safe(tool_fn, name: str, *args, timeout: float = 6, max_retries: int = 2):
    """
    Call an async intel tool with timeout + retries.
    Returns None on all failures — never raises.
    Logs to audit_log on terminal failure.
    """
    for attempt in range(max_retries + 1):
        try:
            return await asyncio.wait_for(tool_fn(*args), timeout=timeout)
        except (asyncio.TimeoutError, Exception) as e:
            if attempt == max_retries:
                logger.warning("[investigation_agent] tool %s failed after %d attempts: %s", name, max_retries + 1, e)
                try:
                    from cloud_db import write_audit_log
                    write_audit_log(
                        agent    = AGENT_NAME,
                        action   = "TOOL_FAILURE",
                        metadata = {"tool": name, "error": str(e)},
                    )
                except Exception:
                    pass
                return None
            await asyncio.sleep(1)


# ── Gemini investigation prompt ───────────────────────────────────────────────

def _build_investigation_prompt(payload: dict, evidence: dict) -> str:
    import html
    safe_url = html.escape(str(payload.get('url', ''))[:200])
    safe_payload = html.escape(str(payload.get('payload', ''))[:200])
    return f"""You are a senior cybersecurity analyst. Analyze this security alert and the gathered threat intelligence.
Return ONLY valid JSON with exactly these keys:
{{
  "attack_type": "<string>",
  "confidence": <float 0-1>,
  "mitre_tags": ["<technique_id>", ...],
  "kill_chain_phase": "<phase>",
  "ip_reputation": "<CLEAN|SUSPICIOUS|MALICIOUS>",
  "evidence_summary": "<2-3 sentence summary>",
  "recommended_action": "<BLOCK|RATE_LIMIT|MONITOR|IGNORE>",
  "threat_score": <float 0-100>
}}

Alert:
  IP: {payload.get('ip', 'unknown')}
  Attack type: {payload.get('attack_type', 'unknown')}
  Rule match: {payload.get('rule_match', 'none')}
  ML score: {payload.get('ml_score', 0):.3f}
  Verdict: {payload.get('verdict', 'unknown')}
  URL: {safe_url}
  Payload: {safe_payload}
  Kill chain phase: {payload.get('kill_chain_phase', 'unknown')}
  MITRE tags: {payload.get('mitre_tags', [])}
  Session - escalating: {payload.get('session_flags', {}).get('is_escalating', False)}
  Session - multi_vector: {payload.get('session_flags', {}).get('is_multi_vector', False)}

Threat Intelligence:
  AbuseIPDB: {json.dumps(evidence.get('abuseipdb'), indent=2) if evidence.get('abuseipdb') else 'unavailable'}
  VirusTotal: {json.dumps(evidence.get('virustotal'), indent=2) if evidence.get('virustotal') else 'unavailable'}
  WHOIS: {json.dumps(evidence.get('whois'), indent=2) if evidence.get('whois') else 'unavailable'}

Return ONLY the JSON object, no markdown, no explanation."""


def _parse_gemini_json(text: str) -> Optional[dict]:
    """Defensively parse JSON from Gemini response."""
    # Strip markdown code fences if present
    text = re.sub(r"```(?:json)?", "", text).strip().strip("`")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to extract JSON object
        match = re.search(r'\{[\s\S]+\}', text)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return None
    return None


def _rule_based_verdict(payload: dict) -> dict:
    """Fallback verdict when Gemini fails — derived from existing signal."""
    ml_score   = payload.get("ml_score", 0)
    rule_match = payload.get("rule_match")
    threat_score = ml_score * 70 + (30 if rule_match else 0)
    action = "BLOCK" if threat_score > 80 else "RATE_LIMIT" if threat_score > 50 else "MONITOR"
    return {
        "attack_type":        payload.get("attack_type", "UNKNOWN"),
        "confidence":         round(ml_score, 3),
        "mitre_tags":         [t["technique_id"] for t in payload.get("mitre_tags", [])],
        "kill_chain_phase":   payload.get("kill_chain_phase", "Delivery"),
        "ip_reputation":      "SUSPICIOUS" if threat_score > 50 else "CLEAN",
        "evidence_summary":   f"Rule-based verdict (Gemini unavailable). Rule: {rule_match}, ML: {ml_score:.3f}",
        "recommended_action": action,
        "threat_score":       round(threat_score, 1),
    }


# ── Main processing logic ─────────────────────────────────────────────────────

async def _process_message(msg: dict) -> None:
    from cloud_db import (
        update_queue_message, write_audit_log, update_agent_status,
        write_to_queue
    )

    msg_id   = msg["id"]
    alert_id = msg.get("alert_id")
    payload  = msg.get("payload", {})
    ip       = payload.get("ip", "")

    update_agent_status(AGENT_NAME, "BUSY", alert_id)
    update_queue_message(msg_id, {"status": "PROCESSING"})

    # ── 1. Gather threat intelligence (parallel, with circuit breaker) ────────
    from intel.threat_enrichment import check_abuseipdb, check_virustotal_ip, check_whois
    from urllib.parse import urlparse

    domain = None
    raw_url = payload.get("url", "")
    try:
        parsed = urlparse(raw_url if raw_url.startswith("http") else "http://" + raw_url)
        domain = parsed.netloc or None
    except Exception:
        pass

    abuse_task = asyncio.create_task(call_tool_safe(check_abuseipdb,   "abuseipdb",  ip))
    vt_task    = asyncio.create_task(call_tool_safe(check_virustotal_ip,"virustotal", ip))
    whois_task = asyncio.create_task(call_tool_safe(check_whois, "whois", domain)) if domain else None

    abuse  = await abuse_task
    vt     = await vt_task
    whois  = await whois_task if whois_task else None

    evidence = {
        "abuseipdb": abuse,
        "virustotal": vt,
        "whois": whois,
    }

    # ── 2. Gemini investigation ───────────────────────────────────────────────
    gemini_verdict: Optional[dict] = None

    if _client:
        try:
            prompt   = _build_investigation_prompt(payload, evidence)
            loop     = asyncio.get_event_loop()

            raw_text = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: _client.models.generate_content(
                        model   = GEMINI_MODEL,
                        contents= prompt,
                    ).text
                ),
                timeout=15
            )
            gemini_verdict = _parse_gemini_json(raw_text)

            if gemini_verdict is None:
                logger.warning("[investigation_agent] Gemini JSON parse failed, retrying with stricter prompt...")
                strict_prompt = "Return ONLY valid JSON. No explanation. " + prompt
                raw_text2 = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: _client.models.generate_content(
                            model   = GEMINI_MODEL,
                            contents= strict_prompt,
                        ).text
                    ),
                    timeout=10
                )
                gemini_verdict = _parse_gemini_json(raw_text2)
        except Exception as e:
            logger.warning("[investigation_agent] Gemini call failed: %s -- using rule-based fallback.", e)

    if gemini_verdict is None:
        gemini_verdict = _rule_based_verdict(payload)

    # ── 3. Write to audit_log ─────────────────────────────────────────────────
    write_audit_log(
        agent     = AGENT_NAME,
        action    = "INVESTIGATION_COMPLETE",
        reasoning = gemini_verdict.get("evidence_summary", ""),
        metadata  = {
            "verdict":    gemini_verdict,
            "evidence":   {
                "abuseipdb_score": evidence.get("abuseipdb", {}).get("abuse_confidence") if evidence.get("abuseipdb") else None,
                "vt_malicious":    evidence.get("virustotal", {}).get("malicious")        if evidence.get("virustotal") else None,
            },
        },
        alert_id  = alert_id,
    )

    # ── 4. Route to response_agent ────────────────────────────────────────────
    enriched_payload = {
        **payload,
        "investigation_verdict": gemini_verdict,
        "threat_score":          gemini_verdict.get("threat_score", 50),
        "recommended_action":    gemini_verdict.get("recommended_action", "MONITOR"),
        "ip_reputation":         gemini_verdict.get("ip_reputation", "UNKNOWN"),
    }

    write_to_queue(
        sender   = AGENT_NAME,
        receiver = "response_agent",
        payload  = enriched_payload,
        alert_id = alert_id,
        priority = "HIGH" if gemini_verdict.get("threat_score", 0) > 70 else "MEDIUM",
    )

    update_queue_message(msg_id, {"status": "DONE"})
    update_agent_status(AGENT_NAME, "IDLE")

    logger.info(
        "[investigation_agent] alert=%s threat_score=%.1f action=%s",
        alert_id,
        gemini_verdict.get("threat_score", 0),
        gemini_verdict.get("recommended_action", "MONITOR"),
    )


# ── Dead-letter sweep ─────────────────────────────────────────────────────────

async def _dead_letter_sweep() -> None:
    """Mark messages stuck in PROCESSING > 60s as DEAD_LETTER."""
    from cloud_db import _db, update_queue_message
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=PROCESSING_TIMEOUT)).isoformat()
        res = (
            _db()
            .table("agent_queue")
            .select("id, retry_count")
            .eq("receiver", AGENT_NAME)
            .eq("status", "PROCESSING")
            .lt("updated_at", cutoff)
            .execute()
        )
        for row in (res.data or []):
            retry = row.get("retry_count", 0)
            if retry >= MAX_RETRIES:
                update_queue_message(row["id"], {
                    "status":         "DEAD_LETTER",
                    "failure_reason": f"Stuck in PROCESSING >{PROCESSING_TIMEOUT}s after {retry} retries.",
                })
                logger.error("[investigation_agent] Dead-lettered msg %s", row["id"])
            else:
                update_queue_message(row["id"], {
                    "status":      "PENDING",
                    "retry_count": retry + 1,
                })
                logger.warning("[investigation_agent] Requeued stuck msg %s (retry %d)", row["id"], retry + 1)
    except Exception as e:
        logger.error("[investigation_agent] dead-letter sweep failed: %s", e)


# ── Main poll loop ────────────────────────────────────────────────────────────

async def run_forever() -> None:
    from cloud_db import get_pending_queue_messages, update_agent_status
    update_agent_status(AGENT_NAME, "IDLE")
    logger.info("[investigation_agent] started, polling every %ds.", POLL_INTERVAL)

    sweep_counter = 0
    while True:
        try:
            messages = get_pending_queue_messages(AGENT_NAME, limit=3)
            for msg in messages:
                await _process_message(msg)
        except Exception as e:
            logger.error("[investigation_agent] poll error: %s", e)

        # Run dead-letter sweep every ~30 polls
        sweep_counter += 1
        if sweep_counter >= 30:
            await _dead_letter_sweep()
            sweep_counter = 0

        await asyncio.sleep(POLL_INTERVAL)
