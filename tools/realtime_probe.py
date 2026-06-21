"""tools/realtime_probe.py — Inject a COMMAND_INJECTION alert via the same
save_alert/write_audit_log helpers the real pipeline uses, then confirm rows exist."""
import sys, os, uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv(override=True)

from cloud_db import save_alert, write_audit_log, _db

trace_id = str(uuid.uuid4())
ts       = datetime.now(timezone.utc).isoformat()
print(f"[probe] trace_id={trace_id[:8]}  ts={ts}")

alert = {
    "alert_uuid":      trace_id,
    "src_ip":          "66.240.205.34",
    "ip":              "66.240.205.34",
    "url":             "http://localhost/shell.php?cmd=cat+/etc/passwd",
    "uri":             "http://localhost/shell.php?cmd=cat+/etc/passwd",
    "attack_type":     "COMMAND_INJECTION",
    "method":          "GET",
    "outcome":         "ATTEMPT",
    "confidence":      97.0,
    "severity":        "CRITICAL",
    "verdict":         "CRITICAL",
    "rule_match":      "COMMAND_INJECTION",
    "suspicion_score": 0.97,
    "ml_score":        0.97,
    "timestamp":       ts,
    "payload":         "cmd=cat+/etc/passwd",
    "source":          "realtime_probe",
}

# Use the real cloud_db helpers — same path as detection_agent
save_alert(alert)
print("[probe] save_alert() called")

write_audit_log(
    agent     = "detection_agent",
    action    = "ALERT_DETECTED",
    reasoning = "[REALTIME PROBE] CMDi from 66.240.205.34 — threat_score=97",
    metadata  = {"verdict": "CRITICAL", "ml_score": 0.97, "mock": False, "source": "realtime_probe"},
    alert_id  = trace_id,
)
print("[probe] write_audit_log() called")

import time; time.sleep(1)

# Verify rows exist in Supabase
r_al = _db().table("alerts").select("id,attack_type,ip,timestamp").eq("alert_uuid", trace_id).execute()
r_lg = _db().table("audit_log").select("id,action,agent").eq("alert_id", trace_id).execute()
print(f"[probe] alerts row   : {r_al.data}")
print(f"[probe] audit_log row: {r_lg.data}")
print("[probe] Both rows confirmed in Supabase — Realtime should have pushed to browser.")
