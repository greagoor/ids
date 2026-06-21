"""tools/delayed_probe.py — waits 35s then injects, giving the browser time to open and subscribe."""
import sys, os, time, uuid
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv; load_dotenv(override=True)
from datetime import datetime, timezone
from cloud_db import save_alert, write_audit_log, _db

print("[delayed_probe] Sleeping 35s — browser is opening now...", flush=True)
time.sleep(35)

trace_id = str(uuid.uuid4())
ts       = datetime.now(timezone.utc).isoformat()
print(f"[delayed_probe] FIRING NOW  trace_id={trace_id[:8]}  ts={ts}", flush=True)

save_alert({
    "alert_uuid": trace_id, "src_ip": "185.220.101.47",
    "uri": "http://target.com/wp-admin/admin-ajax.php?action=revslider_ajax_action&client_action=update_slide",
    "attack_type": "LFI", "method": "POST", "outcome": "ATTEMPT",
    "confidence": 95, "severity": "CRITICAL", "rule_match": "LFI",
    "suspicion_score": 0.95, "ml_score": 0.95, "timestamp": ts,
})
write_audit_log(
    agent="detection_agent", action="ALERT_DETECTED",
    reasoning="[REALTIME LIVE TEST] LFI from 185.220.101.47 — score=95 — should appear WITHOUT refresh",
    metadata={"verdict": "CRITICAL", "ml_score": 0.95, "mock": False, "source": "delayed_probe"},
    alert_id=trace_id,
)

time.sleep(1)
r = _db().table("audit_log").select("id,action").eq("alert_id", trace_id).execute()
print(f"[delayed_probe] audit_log confirmed: {r.data}", flush=True)
print("[delayed_probe] Done — Supabase pushed via Realtime WS.", flush=True)
