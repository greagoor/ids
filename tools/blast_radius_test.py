"""
tools/blast_radius_test.py — Blast-radius cap verification

Fires 8 high-confidence attacks (threat_score=92) from 8 distinct routable IPs
in rapid sequence through the same response_agent._execute_response() call that
the live system uses.

Proves:
  Q1: First 5 → BLOCK_MOCK  (limiter allows)
  Q2: Next 3  → RATE_LIMIT_MOCK_DOWNGRADED (limiter saturated)
  Q3: audit_log shows the full trail including downgrade reasoning
"""

import sys, os, asyncio, uuid, time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv(override=True)

import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
for noisy in ["httpx", "httpcore", "hpack"]:
    logging.getLogger(noisy).setLevel(logging.WARNING)

SEP = "=" * 68
def section(t): print(f"\n{SEP}\n  {t}\n{SEP}")

# ── 8 distinct routable IPs (TEST-NET + real ASNs, none RFC1918) ──────────────
ATTACKS = [
    # ip,              attack_type,    label
    ("203.0.113.11",  "SQL_INJECTION", "SQLi #1"),
    ("45.33.32.156",  "XSS",           "XSS #1"),
    ("198.51.100.7",  "LFI",           "LFI #1"),
    ("91.108.4.1",    "SQL_INJECTION", "SQLi #2"),
    ("185.220.101.5", "XSS",           "XSS #2"),
    ("5.188.210.33",  "COMMAND_INJECTION","CMDi #1"),   # should be downgraded
    ("80.82.77.139",  "SQL_INJECTION", "SQLi #3"),      # should be downgraded
    ("194.165.16.11", "XSS",           "XSS #3"),       # should be downgraded
]

THREAT_SCORE = 92.0   # well above the > 80 BLOCK threshold


def make_payload(ip: str, attack_type: str, trace_id: str) -> dict:
    return {
        "alert_uuid":      trace_id,
        "ip":              ip,
        "src_ip":          ip,
        "attack_type":     attack_type,
        "verdict":         "HIGH",
        "outcome":         "ATTEMPT",
        "confidence":      95,
        "severity":        "CRITICAL",
        "rule_match":      attack_type,
        "ml_score":        0.95,
        "threat_score":    THREAT_SCORE,     # direct field
        "investigation_verdict": {           # and via Gemini verdict path
            "threat_score":        THREAT_SCORE,
            "recommended_action":  "BLOCK",
            "ip_reputation":       "MALICIOUS",
            "attack_type":         attack_type,
            "confidence":          0.95,
            "mitre_tags":          ["T1190"],
            "kill_chain_phase":    "Exploitation",
            "evidence_summary":    f"High-confidence {attack_type} from {ip}.",
        },
        "recommended_action": "BLOCK",
        "ip_reputation":      "MALICIOUS",
        "mitre_tags":         [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"}],
        "kill_chain_phase":   "Exploitation",
        "session_flags": {
            "ip": ip, "req_per_min": 50, "unique_endpoints": 5,
            "error_ratio": 0.0, "escalation_score": 95.0,
            "is_rapid_fire": True, "is_error_heavy": False,
            "is_multi_vector": True, "is_escalating": True,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "blast_radius_test",
    }


async def run_blast_radius_test():
    from agents.response_agent import _execute_response
    from prevention.firewall   import get_rate_limiter
    from cloud_db              import _db

    # ── Reset rate limiter to clean state for test ────────────────────────────
    limiter = get_rate_limiter()
    limiter._minute_window.clear()
    limiter._hour_window.clear()
    print(f"\n  Rate limiter reset. max_per_minute={limiter.max_per_minute}, max_per_hour={limiter.max_per_hour}")
    print(f"  Firing {len(ATTACKS)} attacks — first {limiter.max_per_minute} should BLOCK, rest DOWNGRADED")
    print()

    trace_ids   = []
    ips         = []
    results     = []   # list of dicts per attack

    section("FIRING 8 HIGH-CONFIDENCE ATTACKS")
    print(f"  {'#':<2} {'Label':<12} {'IP':<18} {'Expected':<28} trace_id[:8]")
    print(f"  {'--':<2} {'-------':<12} {'-'*18} {'-'*28} -----------")

    for i, (ip, attack_type, label) in enumerate(ATTACKS, 1):
        expected = "BLOCK_MOCK" if i <= 5 else "RATE_LIMIT_MOCK_DOWNGRADED"
        tid = str(uuid.uuid4())
        trace_ids.append(tid)
        ips.append(ip)
        print(f"  {i:<2} {label:<12} {ip:<18} {expected:<28} {tid[:8]}")

    print("\n  Executing _execute_response() sequentially...")
    print()

    for i, ((ip, attack_type, label), tid) in enumerate(zip(ATTACKS, trace_ids), 1):
        payload  = make_payload(ip, attack_type, tid)
        msg      = {"id": tid, "alert_id": tid, "payload": payload,
                    "sender": "investigation_agent", "receiver": "response_agent"}

        stats_before = limiter.stats()
        await _execute_response(msg, payload, tid)
        stats_after  = limiter.stats()

        results.append({
            "n":       i,
            "label":   label,
            "ip":      ip,
            "tid":     tid,
            "blocks_before": stats_before["blocks_last_minute"],
            "blocks_after":  stats_after["blocks_last_minute"],
        })
        time.sleep(0.05)   # tiny pause for Supabase writes

    await asyncio.sleep(1.5)   # let all audit_log writes commit

    # ── Q1 & Q2: Query audit_log for response_agent actions ──────────────────
    section("Q1 & Q2 — response_agent actions per alert")

    al_res = (
        _db()
        .table("audit_log")
        .select("alert_id, agent, action, reasoning, metadata, timestamp")
        .in_("alert_id", trace_ids)
        .eq("agent", "response_agent")
        .order("timestamp")
        .execute()
    )
    al_rows = {str(r["alert_id"]): r for r in (al_res.data or [])}

    fw_res = (
        _db()
        .table("audit_log")
        .select("alert_id, agent, action, reasoning, timestamp")
        .in_("alert_id", trace_ids)
        .eq("agent", "firewall")
        .order("timestamp")
        .execute()
    )
    fw_rows = {}
    for r in (fw_res.data or []):
        fw_rows.setdefault(str(r["alert_id"]), []).append(r)

    print(f"\n  {'#':<2} {'Label':<12} {'IP':<18} {'response_agent action':<30} {'firewall action':<22} {'limiter'}")
    print(f"  {'--':<2} {'-------':<12} {'-'*18} {'-'*30} {'-'*22} -------")

    blocks_confirmed = 0
    downgrades_confirmed = 0

    for res in results:
        i, label, ip, tid = res["n"], res["label"], res["ip"], res["tid"]
        al  = al_rows.get(tid, {})
        fws = fw_rows.get(tid, [])
        resp_action = al.get("action", "NOT_FOUND")
        fw_actions  = "/".join(r["action"] for r in fws) or "NOT_FOUND"
        slot = f"{res['blocks_before']}→{res['blocks_after']}"

        is_block    = "BLOCK_MOCK" in resp_action and "DOWNGRADED" not in resp_action
        is_downgrade= "DOWNGRADED" in resp_action
        marker = "BLOCK ✓" if is_block else ("DOWNGRADE ✓" if is_downgrade else "?")

        if is_block:    blocks_confirmed += 1
        if is_downgrade: downgrades_confirmed += 1

        print(f"  {i:<2} {label:<12} {ip:<18} {resp_action:<30} {fw_actions:<22} [{slot}] {marker}")

    print(f"\n  Blocks confirmed     : {blocks_confirmed}/5")
    print(f"  Downgrades confirmed : {downgrades_confirmed}/3")

    # ── Q3: Full audit_log trail with reasoning ────────────────────────────────
    section("Q3 — Full audit_log trail (response_agent + firewall entries)")

    all_al = (
        _db()
        .table("audit_log")
        .select("alert_id, agent, action, reasoning, metadata, timestamp")
        .in_("alert_id", trace_ids)
        .order("timestamp")
        .execute()
    )

    print()
    for r in (all_al.data or []):
        aid     = str(r["alert_id"])[:8]
        agent   = r["agent"]
        action  = r["action"]
        ts      = str(r["timestamp"])[11:19]   # HH:MM:SS
        meta    = r.get("metadata") or {}
        reasoning = str(r.get("reasoning", ""))[:110]

        marker = ""
        if "DOWNGRAD" in action:
            marker = "  ← BLAST RADIUS DOWNGRADE"
        elif "BLOCK_MOCK" == action and agent == "response_agent":
            marker = "  ← BLOCKED"
        elif "BLOCK_MOCK" == action and agent == "firewall":
            marker = "  ← FW LOGGED"

        print(f"\n  [{ts}] agent={agent:<16} action={action}{marker}")
        print(f"          alert_id={aid}  ip={meta.get('ip','?')}")
        print(f"          {reasoning}")

    # ── Final verdict ──────────────────────────────────────────────────────────
    section("FINAL VERDICT")
    q1_pass = (blocks_confirmed == 5)
    q2_pass = (downgrades_confirmed == 3)
    q3_pass = (len(all_al.data or []) >= 8)    # at least 8 audit rows

    final_stats = limiter.stats()
    print(f"\n  Q1 — First 5 BLOCKED              : {'PASS ✓' if q1_pass else f'FAIL ✗ ({blocks_confirmed}/5)'}")
    print(f"  Q2 — Next 3 downgraded to RATE_LIMIT: {'PASS ✓' if q2_pass else f'FAIL ✗ ({downgrades_confirmed}/3)'}")
    print(f"  Q3 — audit_log trail present       : {'PASS ✓' if q3_pass else f'FAIL ✗ ({len(all_al.data or [])} rows)'}")
    print(f"\n  Final limiter state:")
    print(f"    blocks_last_minute : {final_stats['blocks_last_minute']}")
    print(f"    blocks_last_hour   : {final_stats['blocks_last_hour']}")
    print(f"    max_per_minute     : {final_stats['max_per_minute']}")
    print(f"    max_per_hour       : {final_stats['max_per_hour']}")
    print(f"\n  Note: On Linux, these would be real iptables DROP rules.")
    print(f"        On Windows (this run) → MOCK actions logged only.")


asyncio.run(run_blast_radius_test())
