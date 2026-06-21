"""tools/test_verif_only.py"""
import sys, os, uuid, time
from datetime import datetime, timezone, timedelta
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv; load_dotenv(override=True)
from cloud_db import _db

SEP = "=" * 80
def section(t): print(f"\n{SEP}\n{t}\n{SEP}")

# ── VERIFY 1 ──────────────────────────────────────────────────────────────────
section("VERIFY 1: Learning agent / drift detection (Checking DB directly)")
res = _db().table("model_metrics").select("*").order("timestamp", desc=True).limit(2).execute()
if res.data:
    print("Latest model_metrics rows written by learning_agent:")
    for m in res.data:
        print(f"  - drift_detected: {m.get('drift_detected')}, accuracy: {m.get('accuracy')}, f1_score: {m.get('f1_score')}, timestamp: {m.get('timestamp')}")
else:
    print("No model_metrics found. learning_agent failed or didn't write.")

# ── VERIFY 2 ──────────────────────────────────────────────────────────────────
section("VERIFY 2: Watchdog catching a real stuck message")
stuck_id = str(uuid.uuid4())
old_time = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()

# Insert stuck msg
_db().table("agent_queue").insert({
    "id": stuck_id,
    "sender": "test_sender",
    "receiver": "test_receiver",
    "payload": {},
    "status": "PROCESSING",
    "retry_count": 3,  # To force DEAD_LETTER
    "created_at": old_time,
    "updated_at": old_time
}).execute()

print(f"Inserted stuck msg {stuck_id} with status=PROCESSING, retry_count=3, updated > 5 mins ago.")

from agents.watchdog_agent import _reap_stuck_messages
import asyncio
stats = asyncio.run(_reap_stuck_messages())
print(f"Watchdog reaper stats returned: {stats}")

print(f"State AFTER watchdog cycle for msg {stuck_id}:")
res_stuck = _db().table("agent_queue").select("status, retry_count, failure_reason").eq("id", stuck_id).execute()
if res_stuck.data:
    print(res_stuck.data[0])
else:
    print("Row not found.")
