"""
tools/chatbot_rag_test.py — End-to-end RAG chatbot test for IP 10.0.0.41

Steps:
  1. Insert realistic SQLi alert + 5 audit_log entries for 10.0.0.41 into Supabase
  2. Run knowledge_ingest.run_full_ingest() to populate ChromaDB
  3. Call query_rag() and show the EXACT docs retrieved
  4. Call answer_query() and show the Gemini answer
  5. Cross-check: compare Gemini's stated facts against what's actually in the DB

Nothing invented — every claim Gemini makes must trace to a real DB row.
"""

import sys, os, asyncio, uuid
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv(override=True)

import logging
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

SEP = "=" * 68
def section(t): print(f"\n{SEP}\n  {t}\n{SEP}")

# ── Step 1: Insert realistic SQLi test data for 10.0.0.41 ────────────────────
section("STEP 1 — Inserting SQLi test data for 10.0.0.41")

from cloud_db import _db
import datetime as dt

trace_id  = str(uuid.uuid4())
ts        = dt.datetime.now(dt.timezone.utc).isoformat()

# Insert alert
alert_row = {
    "alert_uuid":      trace_id,
    "ip":              "10.0.0.41",
    "url":             "http://internal.corp/api/users?id=1+UNION+SELECT+username,password,NULL+FROM+admin_users--",
    "attack_type":     "SQL_INJECTION",
    "method":          "GET",
    "outcome":         "ATTEMPT",
    "confidence":      88,
    "severity":        3,          # HIGH = 3 in DB
    "rule_match":      "SQL_INJECTION",
    "ml_score":        0.883,
    "suspicion_score": 0.883,
    "timestamp":       ts,
}
r = _db().table("alerts").insert(alert_row).execute()
alert_db_id = r.data[0]["id"] if r.data else "?"
print(f"  alerts INSERT:     id={alert_db_id}  ip=10.0.0.41  attack=SQL_INJECTION")

# Insert 5 audit_log rows covering the full agent chain
audit_rows = [
    {
        "agent":     "detection_agent",
        "action":    "ALERT_DETECTED",
        "reasoning": "SQLi detected: UNION SELECT payload in query string. Rule: SQL_INJECTION. ML score: 0.883. URL: /api/users?id=1+UNION+SELECT+username,password",
        "metadata":  {"verdict": "HIGH", "ml_score": 0.883, "rule_match": "SQL_INJECTION", "mock": False},
        "alert_id":  trace_id,
    },
    {
        "agent":     "pretriage_agent",
        "action":    "ROUTE_TO_INVESTIGATION",
        "reasoning": "INVESTIGATE: SQL injection with ML score 0.883 and confirmed rule match. High confidence attack, warrants full investigation.",
        "metadata":  {"verdict": "HIGH", "gemini_used": True},
        "alert_id":  trace_id,
    },
    {
        "agent":     "investigation_agent",
        "action":    "INVESTIGATION_COMPLETE",
        "reasoning": "Rule-based verdict: SQL_INJECTION with ML=0.883. Payload contains UNION SELECT targeting admin_users table. No AbuseIPDB data available (private RFC1918 IP 10.0.0.41). Kill chain: Exploitation. MITRE T1190.",
        "metadata":  {
            "verdict": {
                "attack_type": "SQL_INJECTION",
                "confidence": 0.883,
                "threat_score": 78.3,
                "ip_reputation": "UNKNOWN",
                "recommended_action": "RATE_LIMIT",
                "mitre_tags": ["T1190"],
                "kill_chain_phase": "Exploitation",
                "evidence_summary": "UNION SELECT payload in /api/users endpoint. Targets admin_users table. ML=0.883."
            },
            "gemini_used": False,
        },
        "alert_id":  trace_id,
    },
    {
        "agent":     "firewall",
        "action":    "BLOCK_REFUSED",
        "reasoning": "BLOCK_REFUSED_PROTECTED_RANGE: 10.0.0.41 is in a protected range (RFC1918 10.0.0.0/8). Block not applied.",
        "metadata":  {"ip": "10.0.0.41", "platform": "Windows", "mock": True},
        "alert_id":  trace_id,
    },
    {
        "agent":     "response_agent",
        "action":    "RATE_LIMIT_MOCK",
        "reasoning": "threat_score=78.3 in 50-80 range → rate-limit. Firewall block refused (protected range). Mock=True.",
        "metadata":  {"threat_score": 78.3, "verdict": "HIGH", "mock": True},
        "alert_id":  trace_id,
    },
]

for ar in audit_rows:
    _db().table("audit_log").insert(ar).execute()
    print(f"  audit_log INSERT:  agent={ar['agent']:<22} action={ar['action']}")

print(f"\n  trace_id: {trace_id[:8]}")
print(f"  All 6 rows written to Supabase.")

# ── Step 2: Run full knowledge ingest into ChromaDB ───────────────────────────
section("STEP 2 — Running knowledge_ingest.run_full_ingest()")
print("  Downloading sentence-transformers if not cached (~90MB first run)...")

from rag.knowledge_ingest import run_full_ingest
ingest_counts = run_full_ingest()
print(f"\n  Ingest results:")
for col, cnt in ingest_counts.items():
    print(f"    {col:<25}: {cnt} docs upserted")

# ── Step 3: Query ChromaDB directly — show EXACT retrieved docs ───────────────
section("STEP 3 — ChromaDB retrieval: EXACT docs for 'Why was IP 10.0.0.41 flagged?'")

from rag.rag_engine import query_rag, format_context_for_prompt

USER_QUERY   = "Why was IP 10.0.0.41 flagged?"
ANALYST_ROLE = "senior"   # senior = IPs not redacted

results = query_rag(USER_QUERY, analyst_role=ANALYST_ROLE)
print(f"\n  Query         : \"{USER_QUERY}\"")
print(f"  Analyst role  : {ANALYST_ROLE}")
print(f"  Docs retrieved: {len(results)}")
print()

for i, r in enumerate(results, 1):
    print(f"  [{i}] collection={r['collection']}  distance={r['distance']}")
    print(f"       {r['document'][:180]}")
    if r["metadata"]:
        print(f"       metadata: {r['metadata']}")
    print()

context = format_context_for_prompt(results)

# ── Step 4: Call Gemini and show the final answer ─────────────────────────────
section("STEP 4 — Gemini answer (via chatbot.answer_query)")

# Fix chatbot to use gemini-2.5-flash (gemini-1.5-flash is unavailable)
import rag.chatbot as _chatbot
_chatbot.GEMINI_MODEL = "gemini-2.5-flash"

result = asyncio.run(_chatbot.answer_query(USER_QUERY, analyst_role=ANALYST_ROLE))

print(f"\n  Sources used: {result['sources']}")
print(f"  Grounded    : {result['grounded']}")
print(f"\n  GEMINI ANSWER:\n")
print(f"  {result['answer'].replace(chr(10), chr(10)+'  ')}")

# ── Step 5: Cross-check — what's actually in the DB for 10.0.0.41? ───────────
section("STEP 5 — Ground truth cross-check (actual DB rows for 10.0.0.41)")

alerts_real = _db().table("alerts").select("id,ip,attack_type,url,severity,ml_score,confidence,rule_match,timestamp").eq("ip", "10.0.0.41").execute()
audit_real  = _db().table("audit_log").select("agent,action,reasoning,metadata").eq("alert_id", trace_id).execute()

print(f"\n  alerts table rows for 10.0.0.41:")
for a in (alerts_real.data or []):
    print(f"    id={a['id']}  attack={a['attack_type']}  severity={a['severity']}  ml={a['ml_score']}  conf={a['confidence']}")
    print(f"    url: {str(a.get('url',''))[:80]}")

print(f"\n  audit_log rows for trace_id {trace_id[:8]}:")
for r in (audit_real.data or []):
    meta = r.get('metadata') or {}
    print(f"    agent={r['agent']:<22} action={r['action']}")
    reasoning_short = str(r.get('reasoning',''))[:100]
    print(f"    reasoning: {reasoning_short}")

# AbuseIPDB check
print(f"\n  AbuseIPDB called?  NO — not present anywhere in the codebase.")
print(f"  IP 10.0.0.41 is RFC1918 (10.0.0.0/8) — even if AbuseIPDB existed,")
print(f"  private IPs are not submitted to threat-intel APIs.")
print(f"\n  If Gemini mentioned any AbuseIPDB score → HALLUCINATION.")
print(f"  If Gemini mentioned RFC1918 / protected range → GROUNDED (from audit_log).")
print(f"  If Gemini mentioned UNION SELECT / admin_users → GROUNDED (from alert url).")
print(f"  If Gemini mentioned MITRE T1190 → GROUNDED (from investigation reasoning).")
print(f"  If Gemini mentioned threat_score=78.3 → GROUNDED (from response_agent).")
