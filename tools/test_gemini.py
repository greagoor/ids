"""tools/test_gemini.py"""
import sys, os, uuid, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv; load_dotenv(override=True)
from cloud_db import _db

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
from agents.investigation_agent import _process_message
import asyncio

try:
    asyncio.run(_process_message(test_msg))
except Exception as e:
    print(f"Error: {e}")

res_audit = _db().table("audit_log").select("metadata").eq("alert_id", test_alert_id).eq("action", "INVESTIGATION_COMPLETE").execute()
if res_audit.data:
    verdict_json = res_audit.data[0]["metadata"].get("verdict")
    print(f"ACTUAL Gemini JSON Response:\n{json.dumps(verdict_json, indent=2)}")
else:
    print("FAILED to get investigation audit_log")
