"""tools/test_fixes_verif.py — Runs verifications and prints evidence for the user"""
import sys, os, time, uuid, json
from datetime import datetime, timezone, timedelta
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv; load_dotenv(override=True)
from cloud_db import _db

SEP = "=" * 80
def section(t): print(f"\n{SEP}\n{t}\n{SEP}")

# ── FIX 1: Test XSS through investigation_agent ─────────────────────────────
section("FIX 1: Testing XSS payload in investigation_agent")
from agents.investigation_agent import _process_message
import asyncio

test_alert_id = str(uuid.uuid4())
test_msg = {
    "id": str(uuid.uuid4()),
    "alert_id": test_alert_id,
    "payload": {
        "ip": "203.0.113.100",
        "attack_type": "XSS",
        "url": "http://127.0.0.1/search?q=<script>alert(document.cookie)</script>",
        "payload": "<script>alert(document.cookie)</script>",
        "verdict": "MEDIUM"
    }
}
_db().table("agent_queue").insert({
    "id": test_msg["id"],
    "sender": "detection_agent",
    "receiver": "investigation_agent",
    "payload": test_msg["payload"],
    "alert_id": test_alert_id,
    "status": "PENDING"
}).execute()

print("Running _process_message on XSS payload...")
try:
    asyncio.run(_process_message(test_msg))
except Exception as e:
    print(f"Error: {e}")

# Read audit_log for the Gemini response
res_audit = _db().table("audit_log").select("metadata").eq("alert_id", test_alert_id).eq("action", "INVESTIGATION_COMPLETE").execute()
if res_audit.data:
    verdict_json = res_audit.data[0]["metadata"].get("verdict")
    print(f"ACTUAL Gemini JSON Response:\n{json.dumps(verdict_json, indent=2)}")
else:
    print("FAILED to get investigation audit_log")

# ── FIX 2: Blocklist fast-path sub-second test ──────────────────────────────
section("FIX 2: Blocklist fast-path sub-second test")
ATTACKER_IP_2 = "203.0.113.102"
try:
    _db().table("blocklist_cache").delete().eq("ip", ATTACKER_IP_2).execute()
except: pass

from intel.blocklist import add_to_blocklist
add_to_blocklist(ATTACKER_IP_2, source="test", score=100.0, hours=1)

print("Warming up ML pipeline first to avoid cold-start penalties...")
from agents.detection_agent import run_detection
run_detection(ip="127.0.0.1", method="GET", url="http://127.0.0.1/demo/target", raw_payload="warmup")

import time
print("Sending 3rd unrelated request to /demo/target (fast-path should block instantly)...")
t0 = time.time()
alert = run_detection(
    ip=ATTACKER_IP_2,
    method="GET",
    url="http://127.0.0.1/demo/target?q=test",
    raw_payload="test",
)
t1 = time.time()
print(f"Detection pipeline took: {(t1 - t0):.3f} seconds")
print(f"Verdict returned: {alert.get('verdict')} (Severity: {alert.get('severity')})")

# ── VERIFY 1: Learning agent / drift detection ──────────────────────────────
section("VERIFY 1: Learning agent / drift detection")
from agents.learning_agent import run_learning_cycle
import random

# Insert 5 fake feedback rows
for i in range(5):
    _db().table("feedback").insert({
        "alert_id": str(uuid.uuid4()),
        "analyst": "test_bot",
        "verdict": random.choice(["TP", "TP", "TP", "FP", "TP"]),
        "notes": "Fake feedback for learning agent test"
    }).execute()

print("Running learning_agent._poll_feedback()...")
from agents.learning_agent import _poll_feedback
import asyncio
asyncio.run(_poll_feedback())

print("\nDid it write to model_metrics?")
res_metrics = _db().table("model_metrics").select("*").order("timestamp", desc=True).limit(2).execute()
for m in res_metrics.data:
    print(m)

# ── VERIFY 2: Watchdog catching a stuck message ─────────────────────────────
section("VERIFY 2: Watchdog agent catching stuck message")
stuck_id = str(uuid.uuid4())
old_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
_db().table("agent_queue").insert({
    "id": stuck_id,
    "sender": "test",
    "receiver": "test",
    "payload": {},
    "status": "PROCESSING",
    "retry_count": 0,
    "created_at": old_time,
    "updated_at": old_time
}).execute()

print(f"Inserted stuck msg {stuck_id} with status=PROCESSING updated 5 mins ago.")

from agents.watchdog_agent import _reap_stuck_messages
import asyncio
asyncio.run(_reap_stuck_messages())

print(f"State AFTER watchdog cycle:")
res_stuck = _db().table("agent_queue").select("status, retry_count, failure_reason").eq("id", stuck_id).execute()
if res_stuck.data:
    print(res_stuck.data[0])
else:
    print("Row not found.")
