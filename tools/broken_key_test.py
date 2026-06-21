"""
tools/broken_key_test.py — Tests graceful Gemini degradation with invalid API key.

Phase A: Override GEMINI_API_KEY with garbage, run full XSS chain.
Phase B: Restore real key, re-run chain — confirm everything works.

Questions answered:
  1. Does investigation_agent crash, hang, or fail gracefully?
  2. Does it fall back to a rule-derived verdict?
  3. Does the alert reach response_agent and get a final disposition,
     or get stuck in agent_queue forever?
  4. Does restoring the real key bring everything back to normal?
"""

import os, sys, time, uuid, asyncio, importlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv(override=True)

REAL_KEY    = os.environ.get("GEMINI_API_KEY", "")
BROKEN_KEY  = "BROKEN-INVALID-KEY-12345"

SEP = "=" * 68
def section(t): print(f"\n{SEP}\n  {t}\n{SEP}")

import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
# Silence httpx noise but keep agent logs
for noisy in ["httpx", "httpcore", "hpack", "google_genai"]:
    logging.getLogger(noisy).setLevel(logging.WARNING)

# ── Build a standard XSS alert payload ────────────────────────────────────────
def make_xss_alert(trace_id: str) -> dict:
    return {
        "alert_uuid":      trace_id,
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "ip":              "203.0.113.7",
        "src_ip":          "203.0.113.7",
        "method":          "POST",
        "uri":             "http://localhost/search?q=<script>alert(document.cookie)</script>",
        "url":             "http://localhost/search?q=<script>alert(document.cookie)</script>",
        "attack_type":     "XSS",
        "outcome":         "ATTEMPT",
        "confidence":      100,
        "severity":        "CRITICAL",
        "verdict":         "MEDIUM",
        "rule_match":      "XSS",
        "ml_score":        0.3386,
        "suspicion_score": 0.3386,
        "shap_features":   [{"feature": "phish_encoded_chars", "value": 0.8}],
        "payload":         "q=<script>alert(document.cookie)</script>",
        "mitre_tags":      [{"technique_id": "T1059.007", "technique_name": "JavaScript"}],
        "kill_chain_phase": "Exploitation",
        "was_obfuscated":  False,
        "session_flags": {
            "ip": "203.0.113.7", "req_per_min": 3, "unique_endpoints": 1,
            "error_ratio": 0.0, "escalation_score": 6.77,
            "is_rapid_fire": False, "is_error_heavy": False,
            "is_multi_vector": False, "is_escalating": False,
        },
        "source": "tshark",
    }


async def run_chain(trace_id: str, phase_label: str) -> dict:
    """Run the pretriage → investigation → response chain for one alert."""
    from cloud_db import (
        write_to_queue, _db, write_audit_log, update_agent_status
    )

    results = {
        "trace_id":            trace_id,
        "pretriage_action":    None,
        "pretriage_reasoning": None,
        "pretriage_used_gemini": False,
        "investigation_action": None,
        "investigation_verdict": None,
        "investigation_used_gemini": False,
        "response_action":     None,
        "queue_final_status":  None,
        "incidents_updated":   False,
        "stuck":               False,
    }

    alert = make_xss_alert(trace_id)

    # ── Step 1: Insert into agent_queue ────────────────────────────────────────
    write_to_queue(
        sender   = "detection_agent",
        receiver = "pretriage_agent",
        payload  = alert,
        alert_id = trace_id,
        priority = "MEDIUM",
    )
    await asyncio.sleep(0.3)

    q_res = (
        _db().table("agent_queue").select("id, status")
        .eq("alert_id", trace_id).eq("receiver", "pretriage_agent")
        .order("created_at", desc=True).limit(1).execute()
    )
    q_row = q_res.data[0] if q_res.data else {}
    PRETRIAGE_MSG_ID = q_row.get("id")
    print(f"  [{phase_label}] Step 1: queue row id={PRETRIAGE_MSG_ID} status={q_row.get('status')}")

    # ── Step 2: pretriage_agent ─────────────────────────────────────────────────
    # Reimport to pick up fresh API key (patched in env before this call)
    import agents.pretriage_agent as _pt
    importlib.reload(_pt)

    pt_msg = {
        "id": PRETRIAGE_MSG_ID, "alert_id": trace_id,
        "payload": alert, "sender": "detection_agent",
        "receiver": "pretriage_agent", "priority": "MEDIUM",
    }
    t_pretriage_start = time.perf_counter()
    await _pt._process_message(pt_msg)
    t_pretriage_elapsed = (time.perf_counter() - t_pretriage_start) * 1000

    await asyncio.sleep(0.3)
    al_pt = (
        _db().table("audit_log").select("action, reasoning, metadata, timestamp")
        .eq("alert_id", trace_id).eq("agent", "pretriage_agent")
        .order("timestamp", desc=True).limit(1).execute()
    )
    al_pt_row = al_pt.data[0] if al_pt.data else {}
    results["pretriage_action"]    = al_pt_row.get("action")
    results["pretriage_reasoning"] = al_pt_row.get("reasoning", "")
    meta = al_pt_row.get("metadata") or {}
    results["pretriage_used_gemini"] = "fail-safe" not in al_pt_row.get("reasoning", "").lower() \
                                       and "gemini unavailable" not in al_pt_row.get("reasoning", "").lower()

    print(f"  [{phase_label}] Step 2 pretriage: {al_pt_row.get('action')} ({t_pretriage_elapsed:.0f} ms)")
    print(f"    reasoning: {str(al_pt_row.get('reasoning',''))[:120]}")
    print(f"    gemini_used: {results['pretriage_used_gemini']}")

    # Find next queue message
    next_res = (
        _db().table("agent_queue").select("id, receiver, payload")
        .eq("alert_id", trace_id)
        .in_("receiver", ["investigation_agent", "response_agent"])
        .order("created_at", desc=True).limit(1).execute()
    )
    next_row     = next_res.data[0] if next_res.data else {}
    NEXT_MSG_ID  = next_row.get("id")
    NEXT_RECEIVER = next_row.get("receiver", "investigation_agent")
    next_payload = next_row.get("payload", alert)
    print(f"  [{phase_label}] Step 2 output: → {NEXT_RECEIVER} msg_id={NEXT_MSG_ID}")

    # ── Step 3: investigation_agent (if routed there) ─────────────────────────
    if NEXT_RECEIVER == "investigation_agent":
        import agents.investigation_agent as _inv
        importlib.reload(_inv)

        inv_msg = {
            "id": NEXT_MSG_ID, "alert_id": trace_id,
            "payload": next_payload, "sender": "pretriage_agent",
            "receiver": "investigation_agent", "priority": "MEDIUM",
        }
        t_inv_start = time.perf_counter()
        try:
            await _inv._process_message(inv_msg)
            hung = False
        except Exception as e:
            print(f"  [{phase_label}] Step 3 EXCEPTION: {e}")
            hung = True

        t_inv_elapsed = (time.perf_counter() - t_inv_start) * 1000

        await asyncio.sleep(0.3)
        al_inv = (
            _db().table("audit_log").select("action, reasoning, metadata")
            .eq("alert_id", trace_id).eq("agent", "investigation_agent")
            .order("timestamp", desc=True).limit(1).execute()
        )
        al_inv_row = al_inv.data[0] if al_inv.data else {}
        results["investigation_action"]  = al_inv_row.get("action")
        meta_inv = al_inv_row.get("metadata") or {}
        verdict_data = meta_inv.get("verdict", {})
        results["investigation_verdict"] = verdict_data
        results["investigation_used_gemini"] = "rule-based" not in str(al_inv_row.get("reasoning","")).lower()
        results["hung"] = hung

        print(f"  [{phase_label}] Step 3 investigation: {al_inv_row.get('action')} ({t_inv_elapsed:.0f} ms)")
        print(f"    reasoning: {str(al_inv_row.get('reasoning',''))[:120]}")
        print(f"    gemini_used: {results['investigation_used_gemini']}")
        print(f"    verdict: {verdict_data}")

        # Find response_agent row
        resp_res = (
            _db().table("agent_queue").select("id, payload")
            .eq("alert_id", trace_id).eq("receiver", "response_agent")
            .order("created_at", desc=True).limit(1).execute()
        )
        resp_row = resp_res.data[0] if resp_res.data else {}
        RESP_MSG_ID  = resp_row.get("id")
        resp_payload = resp_row.get("payload", next_payload)
    else:
        RESP_MSG_ID  = NEXT_MSG_ID
        resp_payload = next_payload

    if not RESP_MSG_ID:
        results["stuck"] = True
        print(f"  [{phase_label}] Step 4: NO response_agent row found — alert STUCK ✗")
        return results

    # ── Step 4: response_agent ─────────────────────────────────────────────────
    full_resp = (
        _db().table("agent_queue").select("*")
        .eq("id", RESP_MSG_ID).execute()
    )
    full_resp_row = full_resp.data[0] if full_resp.data else {}
    final_payload = full_resp_row.get("payload", resp_payload)

    from agents.response_agent import _execute_response
    resp_msg = {
        "id": RESP_MSG_ID, "alert_id": trace_id,
        "payload": final_payload, "sender": NEXT_RECEIVER,
        "receiver": "response_agent",
    }
    await _execute_response(resp_msg, final_payload, trace_id)
    await asyncio.sleep(0.3)

    al_resp = (
        _db().table("audit_log").select("action, reasoning, metadata")
        .eq("alert_id", trace_id).eq("agent", "response_agent")
        .order("timestamp", desc=True).limit(1).execute()
    )
    al_resp_row = al_resp.data[0] if al_resp.data else {}
    results["response_action"] = al_resp_row.get("action")
    print(f"  [{phase_label}] Step 4 response: {al_resp_row.get('action')}")
    print(f"    reasoning: {str(al_resp_row.get('reasoning',''))[:120]}")

    # ── Step 5: Check queue message final status ──────────────────────────────
    final_q = (
        _db().table("agent_queue").select("status")
        .eq("id", RESP_MSG_ID).execute()
    )
    results["queue_final_status"] = (final_q.data[0] or {}).get("status") if final_q.data else "NOT_FOUND"
    print(f"  [{phase_label}] Step 5 queue final status: {results['queue_final_status']}")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE A — BROKEN KEY
# ═══════════════════════════════════════════════════════════════════════════════
section("PHASE A — BROKEN GEMINI_API_KEY (invalid key injected)")
print(f"  Patching GEMINI_API_KEY: {REAL_KEY[:8]}... → {BROKEN_KEY}")

os.environ["GEMINI_API_KEY"] = BROKEN_KEY

trace_a = str(uuid.uuid4())
print(f"  trace_id: {trace_a}")
print()

results_a = asyncio.run(run_chain(trace_a, "BROKEN"))

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE B — RESTORED KEY
# ═══════════════════════════════════════════════════════════════════════════════
section("PHASE B — RESTORED GEMINI_API_KEY (real key)")
print(f"  Restoring GEMINI_API_KEY: → {REAL_KEY[:8]}...")

os.environ["GEMINI_API_KEY"] = REAL_KEY

trace_b = str(uuid.uuid4())
print(f"  trace_id: {trace_b}")
print()

results_b = asyncio.run(run_chain(trace_b, "RESTORED"))


# ═══════════════════════════════════════════════════════════════════════════════
# FINAL REPORT
# ═══════════════════════════════════════════════════════════════════════════════
section("FINAL REPORT")

def yn(val): return "YES" if val else "NO"
def ok(val): return "✓" if val else "✗"

print(f"""
  ┌─────────────────────────────────────────────────────────────────┐
  │                  BROKEN KEY (Phase A)                           │
  ├─────────────────────────────────────────────────────────────────┤
  │  Q1: investigation_agent crashed/hung?   {yn(results_a.get('hung',False)):<5} (hung={results_a.get('hung',False)})           │
  │      → Outcome: {'FAIL-SAFE FALLBACK (no crash)' if not results_a.get('hung') else 'CRASHED'}                          │
  │  Q2: Rule-derived verdict used?          {yn(not results_a.get('investigation_used_gemini',True)):<5}                   │
  │      → pretriage gemini used:    {yn(results_a.get('pretriage_used_gemini'))}                         │
  │      → investigation gemini used:{yn(results_a.get('investigation_used_gemini'))}                         │
  │  Q3: Alert reached response_agent?       {yn(results_a.get('response_action') is not None):<5}                   │
  │      → response action: {str(results_a.get('response_action','NONE')):<40}│
  │      → queue stuck?     {yn(results_a.get('stuck',False))}                                      │
  │      → final queue status: {str(results_a.get('queue_final_status','?')):<37}│
  ├─────────────────────────────────────────────────────────────────┤
  │                  RESTORED KEY (Phase B)                         │
  ├─────────────────────────────────────────────────────────────────┤
  │  Q4: Everything works again?             {yn(results_b.get('response_action') is not None):<5}                   │
  │      → pretriage gemini used: {yn(results_b.get('pretriage_used_gemini'))}                          │
  │      → investigation gemini used: {yn(results_b.get('investigation_used_gemini'))}                      │
  │      → response action: {str(results_b.get('response_action','NONE')):<40}│
  │      → final queue status: {str(results_b.get('queue_final_status','?')):<37}│
  └─────────────────────────────────────────────────────────────────┘
""")

print("  Gemini verdict comparison:")
v_a = results_a.get("investigation_verdict", {})
v_b = results_b.get("investigation_verdict", {})
fields = ["attack_type","confidence","threat_score","ip_reputation","recommended_action","kill_chain_phase"]
print(f"  {'Field':<25} {'BROKEN KEY':>18}   {'RESTORED KEY':>18}")
print(f"  {'-'*25} {'-'*18}   {'-'*18}")
for f in fields:
    a_val = str(v_a.get(f, 'N/A'))
    b_val = str(v_b.get(f, 'N/A'))
    print(f"  {f:<25} {a_val:>18}   {b_val:>18}")
