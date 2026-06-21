"""Full bug investigation using direct Supabase REST — no .env needed"""
import urllib.request, json, os

SUPABASE_URL = "https://nqhmyubxbemwhckqzyjm.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5xaG15dWJ4YmVtd2hja3F6eWptIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjcyNzMyNjcsImV4cCI6MjA4Mjg0OTI2N30.r382XoEZ413P9fjjLBYu4cu9S5ULGcNWFHUctSnTAKo"
HEADERS = {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}

def query(table, select="*", extra=""):
    url = f"{SUPABASE_URL}/rest/v1/{table}?select={select}{extra}"
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

SEP = "\n" + "="*60

# BUG 1/2/3 — Alerts: severity + suspicion_score
print(SEP, "\nBUG 1-3: ALERTS TABLE")
alerts = query("alerts", "severity,suspicion_score,confidence,verdict,attack_type", "&limit=10")
print(f"Sample rows ({len(alerts)}):")
for a in alerts[:5]: print(" ", a)

# Count all for distribution
all_alerts = query("alerts", "severity,suspicion_score")
print(f"\nTotal alerts: {len(all_alerts)}")
from collections import Counter
sev = Counter(a['severity'] for a in all_alerts)
print(f"Severity distribution: {dict(sev)}")
susp = [a['suspicion_score'] for a in all_alerts]
none_ct = sum(1 for s in susp if s is None)
real = [s for s in susp if s is not None]
print(f"suspicion_score nulls={none_ct} non-null={len(real)}")
if real: print(f"  range: {min(real):.4f} – {max(real):.4f}, sample: {real[:8]}")

# BUG 5/7 — AI Panel: investigation_verdict + shap_features
print(SEP, "\nBUG 5/7: investigation_verdict & shap_features in alerts")
inv = query("alerts", "id,investigation_verdict,shap_features", "&limit=5")
for r in inv:
    iv = r.get('investigation_verdict')
    shap = r.get('shap_features')
    iv_keys = list(iv.keys()) if isinstance(iv, dict) else iv
    shap_ct = len(shap) if isinstance(shap, list) else shap
    print(f"  id={r['id']} | inv_verdict keys={iv_keys} | shap count={shap_ct}")

# BUG 6 — model_metrics table
print(SEP, "\nBUG 6: model_metrics table")
try:
    mm = query("model_metrics", "*", "&order=timestamp.desc&limit=5")
    print(f"  Rows: {len(mm)}")
    for r in mm[:3]: print(f"  {r}")
except Exception as e: print(f"  ERROR: {e}")

# BUG 12 — blocklist_cache
print(SEP, "\nBUG 12: blocklist_cache")
bl = query("blocklist_cache", "*")
print(f"  Total: {len(bl)}")
for r in bl: print(f"  {r}")

# CHATBOT — knowledge_ingest.py check sources
print(SEP, "\nCHATBOT: honeypot_logs count")
hp = query("honeypot_logs", "id", "&limit=1")
print(f"  honeypot_logs rows: at least {len(hp)}")

print(SEP, "\nAUDIT_LOG investigation_agent samples")
au = query("audit_log", "agent,action,reasoning,metadata",
           "&agent=eq.investigation_agent&limit=3")
for r in au:
    print(f"  action={r['action']}")
    m = r.get('metadata') or {}
    print(f"  metadata keys: {list(m.keys()) if isinstance(m,dict) else m}")
    print(f"  reasoning[:150]: {str(r.get('reasoning',''))[:150]}")
    print()

print("DONE")
