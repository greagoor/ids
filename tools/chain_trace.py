"""
tools/chain_trace.py -- Full XSS alert chain trace (real Supabase + real Gemini)

Drives each agent step directly in sequence, printing actual DB state at
every hand-off. No mocking. Requires SUPABASE_URL, SUPABASE_KEY, GEMINI_API_KEY in .env
"""

import asyncio
import json
import sys
import os
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

SEP = "=" * 68

def section(title):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)

def show_row(label, row):
    print(f"\n  [{label}]")
    for k, v in row.items():
        if isinstance(v, dict):
            print(f"    {k}: {json.dumps(v, indent=6)[:300]}")
        elif isinstance(v, list):
            print(f"    {k}: {v[:3]}")
        else:
            val_str = str(v)
            print(f"    {k}: {val_str[:160]}")


async def run_trace():
    from cloud_db import (
        write_to_queue, get_pending_queue_messages, _db,
        write_audit_log, update_agent_status
    )

    # ------------------------------------------------------------------
    # STEP 0: Build the XSS alert that _bridge_pipeline would produce
    # ------------------------------------------------------------------
    section("STEP 0 -- Build XSS alert (same struct as _bridge_pipeline output)")

    TRACE_ID = str(uuid.uuid4())
    XSS_ALERT = {
        "alert_uuid":        TRACE_ID,
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "ip":                "203.0.113.7",
        "src_ip":            "203.0.113.7",
        "method":            "POST",
        "uri":               "http://localhost/search?q=<script>alert(document.cookie)</script>",
        "url":               "http://localhost/search?q=<script>alert(document.cookie)</script>",
        "attack_type":       "XSS",
        "outcome":           "ATTEMPT",
        "confidence":        100,
        "severity":          "CRITICAL",
        "verdict":           "MEDIUM",
        "rule_match":        "XSS",
        "ml_score":          0.3386,
        "suspicion_score":   0.3386,
        "shap_features":     [
            {"feature": "phish_encoded_chars", "value": 0.8},
            {"feature": "phish_param_count",   "value": 0.6},
        ],
        "payload":           "q=<script>alert(document.cookie)</script>",
        "payload_attack_type": "XSS",
        "mitre_tags":        [{"technique_id": "T1059.007", "technique_name": "JavaScript"}],
        "kill_chain_phase":  "Exploitation",
        "was_obfuscated":    False,
        "session_flags": {
            "ip": "203.0.113.7", "req_per_min": 3, "unique_endpoints": 1,
            "error_ratio": 0.0, "escalation_score": 6.77,
            "is_rapid_fire": False, "is_error_heavy": False,
            "is_multi_vector": False, "is_escalating": False,
        },
        "source": "tshark",
    }

    print(f"  alert_uuid  : {TRACE_ID}")
    print(f"  ip          : {XSS_ALERT['ip']}")
    print(f"  attack_type : {XSS_ALERT['attack_type']}")
    print(f"  url         : {XSS_ALERT['url'][:80]}")
    print(f"  ml_score    : {XSS_ALERT['ml_score']}")
    print(f"  verdict     : {XSS_ALERT['verdict']}")

    # ------------------------------------------------------------------
    # STEP 1: Insert into agent_queue (as _bridge_pipeline does)
    # ------------------------------------------------------------------
    section("STEP 1 -- Insert into agent_queue  (receiver=pretriage_agent)")

    write_to_queue(
        sender   = "detection_agent",
        receiver = "pretriage_agent",
        payload  = XSS_ALERT,
        alert_id = TRACE_ID,
        priority = "MEDIUM",
    )
    print("  write_to_queue() called -- querying to confirm row...")

    await asyncio.sleep(0.5)

    res = (
        _db()
        .table("agent_queue")
        .select("id, sender, receiver, status, priority, alert_id, created_at, payload")
        .eq("alert_id", TRACE_ID)
        .eq("receiver", "pretriage_agent")
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    q_row = res.data[0] if res.data else {}
    PRETRIAGE_MSG_ID = q_row.get("id")
    show_row("agent_queue row", {k: v for k, v in q_row.items() if k != "payload"})
    print(f"\n  payload keys: {list((q_row.get('payload') or {}).keys())}")
    print(f"  RESULT: Row confirmed in agent_queue -- id={PRETRIAGE_MSG_ID}")

    # ------------------------------------------------------------------
    # STEP 2: pretriage_agent picks it up (real Gemini call)
    # ------------------------------------------------------------------
    section("STEP 2 -- pretriage_agent processes alert (real Gemini Flash call)")

    from agents.pretriage_agent import _process_message as pretriage_process

    # Build msg struct as get_pending_queue_messages returns it
    pretriage_msg = {
        "id":        PRETRIAGE_MSG_ID,
        "alert_id":  TRACE_ID,
        "payload":   q_row.get("payload", XSS_ALERT),
        "sender":    "detection_agent",
        "receiver":  "pretriage_agent",
        "priority":  "MEDIUM",
    }

    print("  Calling pretriage_agent._process_message()...")
    print("  (Making real Gemini Flash API call...)")

    await pretriage_process(pretriage_msg)

    # Read audit_log for pretriage decision
    await asyncio.sleep(0.5)
    al_res = (
        _db()
        .table("audit_log")
        .select("agent, action, reasoning, metadata, timestamp")
        .eq("alert_id", TRACE_ID)
        .eq("agent", "pretriage_agent")
        .order("timestamp", desc=True)
        .limit(1)
        .execute()
    )
    al_row = al_res.data[0] if al_res.data else {}
    show_row("audit_log (pretriage decision)", al_row)

    # Find next queue message
    next_res = (
        _db()
        .table("agent_queue")
        .select("id, sender, receiver, status, priority, alert_id, created_at")
        .eq("alert_id", TRACE_ID)
        .in_("receiver", ["investigation_agent", "response_agent"])
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    next_row = next_res.data[0] if next_res.data else {}
    NEXT_MSG_ID  = next_row.get("id")
    NEXT_RECEIVER = next_row.get("receiver", "investigation_agent")
    show_row("New agent_queue row (pretriage output)", next_row)
    print(f"\n  RESULT: pretriage_agent routed to [{NEXT_RECEIVER}]")
    print(f"  Gemini decision: {al_row.get('action', 'unknown')}")
    print(f"  Gemini reasoning snippet: {str(al_row.get('reasoning',''))[:200]}")

    # ------------------------------------------------------------------
    # STEP 3: investigation_agent (real Gemini + threat intel)
    # ------------------------------------------------------------------
    section(f"STEP 3 -- investigation_agent processes alert (real Gemini call + threat intel)")

    # Fetch full payload for next receiver
    full_next = (
        _db()
        .table("agent_queue")
        .select("*")
        .eq("id", NEXT_MSG_ID)
        .execute()
    )
    full_next_row = full_next.data[0] if full_next.data else {}
    inv_payload = full_next_row.get("payload", XSS_ALERT)

    if NEXT_RECEIVER == "investigation_agent":
        from agents.investigation_agent import _process_message as inv_process

        inv_msg = {
            "id":       NEXT_MSG_ID,
            "alert_id": TRACE_ID,
            "payload":  inv_payload,
            "sender":   "pretriage_agent",
            "receiver": "investigation_agent",
            "priority": "MEDIUM",
        }

        print("  Running threat intel tools (AbuseIPDB, VirusTotal, WHOIS)...")
        print("  Making real Gemini Flash investigation call...")

        await inv_process(inv_msg)

        await asyncio.sleep(0.5)
        inv_al = (
            _db()
            .table("audit_log")
            .select("agent, action, reasoning, metadata, timestamp")
            .eq("alert_id", TRACE_ID)
            .eq("agent", "investigation_agent")
            .order("timestamp", desc=True)
            .limit(1)
            .execute()
        )
        inv_al_row = inv_al.data[0] if inv_al.data else {}
        show_row("audit_log (investigation verdict)", inv_al_row)

        meta = inv_al_row.get("metadata", {}) or {}
        verdict_data = meta.get("verdict", {})
        print("\n  === GEMINI INVESTIGATION VERDICT ===")
        for k, v in verdict_data.items():
            print(f"    {k}: {v}")

        # Find response_agent queue row
        resp_res = (
            _db()
            .table("agent_queue")
            .select("id, sender, receiver, status, priority, alert_id, created_at, payload")
            .eq("alert_id", TRACE_ID)
            .eq("receiver", "response_agent")
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        resp_row = resp_res.data[0] if resp_res.data else {}
        RESP_MSG_ID  = resp_row.get("id")
        resp_payload = resp_row.get("payload", inv_payload)
        show_row("agent_queue row (investigation -> response_agent)", {
            k: v for k, v in resp_row.items() if k != "payload"
        })
        print(f"  threat_score in payload: {resp_payload.get('threat_score')}")
        print(f"  recommended_action     : {resp_payload.get('recommended_action')}")
    else:
        # Pretriage went RESPOND_DIRECTLY -- skip investigation
        RESP_MSG_ID  = NEXT_MSG_ID
        resp_payload = inv_payload
        print("  [SKIPPED] pretriage_agent routed RESPOND_DIRECTLY -- no investigation_agent step")

    # ------------------------------------------------------------------
    # STEP 4: response_agent (firewall + incident upsert + audit)
    # ------------------------------------------------------------------
    section("STEP 4 -- response_agent executes response (Windows mock firewall)")

    resp_full = (
        _db()
        .table("agent_queue")
        .select("*")
        .eq("id", RESP_MSG_ID)
        .execute()
    )
    resp_full_row = resp_full.data[0] if resp_full.data else {}
    final_payload = resp_full_row.get("payload", resp_payload)

    from agents.response_agent import _execute_response

    resp_msg = {
        "id":       RESP_MSG_ID,
        "alert_id": TRACE_ID,
        "payload":  final_payload,
        "sender":   NEXT_RECEIVER,
        "receiver": "response_agent",
    }

    print(f"  threat_score entering response_agent: {final_payload.get('threat_score')}")
    print(f"  recommended_action                  : {final_payload.get('recommended_action')}")
    print("  Calling response_agent._execute_response()...")

    await _execute_response(resp_msg, final_payload, TRACE_ID)

    await asyncio.sleep(0.5)

    # Read response audit log
    resp_al = (
        _db()
        .table("audit_log")
        .select("agent, action, reasoning, metadata, timestamp")
        .eq("alert_id", TRACE_ID)
        .eq("agent", "response_agent")
        .order("timestamp", desc=True)
        .limit(1)
        .execute()
    )
    resp_al_row = resp_al.data[0] if resp_al.data else {}
    show_row("audit_log (response_agent action)", resp_al_row)

    # ------------------------------------------------------------------
    # STEP 5: Confirm incidents table
    # ------------------------------------------------------------------
    section("STEP 5 -- incidents table final state")

    inc_res = (
        _db()
        .table("incidents")
        .select("*")
        .eq("ip", "203.0.113.7")
        .order("last_seen", desc=True)
        .limit(1)
        .execute()
    )
    inc_row = inc_res.data[0] if inc_res.data else {}
    show_row("incidents row", inc_row)

    # ------------------------------------------------------------------
    # FULL AUDIT TRAIL
    # ------------------------------------------------------------------
    section("FULL AUDIT TRAIL for this trace")

    all_al = (
        _db()
        .table("audit_log")
        .select("agent, action, reasoning, timestamp")
        .eq("alert_id", TRACE_ID)
        .order("timestamp")
        .execute()
    )
    for i, row in enumerate(all_al.data or [], 1):
        print(f"\n  [{i}] agent={row['agent']}  action={row['action']}")
        print(f"      time={row['timestamp']}")
        print(f"      reasoning={str(row.get('reasoning',''))[:120]}")

    section("TRACE COMPLETE")
    print(f"  alert_uuid : {TRACE_ID}")
    print(f"  ip         : 203.0.113.7")
    print(f"  attack     : XSS")
    print(f"  Chain      : detection_agent -> pretriage_agent -> {NEXT_RECEIVER} -> response_agent")


if __name__ == "__main__":
    asyncio.run(run_trace())
