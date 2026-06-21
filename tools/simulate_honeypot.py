"""tools/simulate_honeypot.py — End-to-end test of honeypot blocklist auto-promotion"""
import sys, os, time, requests
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv; load_dotenv(override=True)
from cloud_db import _db

BASE_URL = "http://127.0.0.1:8000"
ATTACKER_IP = "203.0.113.99"
HEADERS = {"X-Forwarded-For": ATTACKER_IP}

SEP = "=" * 70
def section(t): print(f"\n{SEP}\n  {t}\n{SEP}")

# ── Step 0: Clean slate ───────────────────────────────────────────────────────
# Remove any existing blocklist entry so the test is reproducible
try:
    _db().table("blocklist_cache").delete().eq("ip", ATTACKER_IP).execute()
except: pass

section("STEP 1 & 2: Hits to /admin and /.env from 203.0.113.99")
print(f"  Sending GET /admin")
r1 = requests.get(f"{BASE_URL}/admin", headers=HEADERS)
print(f"  -> Response: {r1.status_code} {r1.text[:30]}")

time.sleep(1)

print(f"  Sending GET /.env")
r2 = requests.get(f"{BASE_URL}/.env", headers=HEADERS)
print(f"  -> Response: {r2.status_code} {r2.text[:30]}")

print("  Waiting 2s for async DB writes...")
time.sleep(2)

# Check honeypot_logs
res_hp = _db().table("honeypot_logs").select("*").eq("ip", ATTACKER_IP).order("timestamp", desc=True).limit(5).execute()
print(f"\n  [Evidence 1] honeypot_logs for {ATTACKER_IP}:")
for r in reversed(res_hp.data or []):
    print(f"    - endpoint={r['endpoint']:<12}  time={r['timestamp']}")

# Check blocklist_cache
res_bl = _db().table("blocklist_cache").select("*").eq("ip", ATTACKER_IP).execute()
print(f"\n  [Evidence 2] blocklist_cache entry for {ATTACKER_IP}:")
if res_bl.data:
    b = res_bl.data[0]
    print(f"    - IP {b['ip']} auto-promoted! source={b['source']} score={b['score']} until={b['blocked_until']}")
else:
    print(f"    - NOT FOUND (Auto-promote failed!)")

section("STEP 3: 3rd unrelated request -> Should hit CRITICAL fast-path")
print(f"  Sending GET /demo/target?q=hello_world (Normal-looking benign request)")
r3 = requests.get(f"{BASE_URL}/demo/target", params={"q": "hello_world"}, headers=HEADERS)
print(f"  -> Response: {r3.status_code}")

print("  Waiting 3s for detection agent to process the alert...")
time.sleep(3)

# Check alerts
res_alerts = _db().table("alerts").select("id,alert_uuid,url,verdict,severity").eq("ip", ATTACKER_IP).order("timestamp", desc=True).limit(3).execute()
print(f"\n  [Evidence 3] Recent alerts for {ATTACKER_IP}:")
for a in (res_alerts.data or []):
    print(f"    - alert_uuid={a.get('alert_uuid','')}  url={a['url'][:30]:<30} verdict={a['verdict']} severity={a['severity']}")

# Find the specific audit_log for the 3rd request
if res_alerts.data:
    third_alert_id = res_alerts.data[0].get("alert_uuid")
    if third_alert_id:
        res_audit = _db().table("audit_log").select("agent,action,reasoning").eq("alert_id", third_alert_id).execute()
        print(f"\n  [Evidence 4] audit_log for 3rd request (alert {third_alert_id[:8]}):")
        for au in (res_audit.data or []):
            print(f"    - agent={au['agent']:<18} action={au['action']:<16}")
            print(f"      reasoning: {au['reasoning']}")
