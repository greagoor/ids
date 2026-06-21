"""Investigation part 2 — avoid column errors"""
import urllib.request, json
from collections import Counter

SUPABASE_URL = "https://nqhmyubxbemwhckqzyjm.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5xaG15dWJ4YmVtd2hja3F6eWptIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjcyNzMyNjcsImV4cCI6MjA4Mjg0OTI2N30.r382XoEZ413P9fjjLBYu4cu9S5ULGcNWFHUctSnTAKo"
HEADERS = {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}

def query(table, select="*", extra=""):
    url = f"{SUPABASE_URL}/rest/v1/{table}?select={select}{extra}"
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

SEP = "\n" + "="*60

# Get ALL column names from alerts
print(SEP, "\nALERTS — full row to see all columns")
full = query("alerts", "*", "&limit=1")
if full:
    print("ALL COLUMN NAMES:", list(full[0].keys()))
    print("FULL ROW:", full[0])

# Bug 5/7 — check what columns exist relating to investigation
print(SEP, "\nALERTS — investigation/shap column check from full row")
if full:
    r = full[0]
    for k,v in r.items():
        if any(x in k for x in ['invest','shap','verdict','ml','susp']):
            print(f"  {k}: {repr(v)[:100]}")

# Bug 6 — model_metrics
print(SEP, "\nMODEL_METRICS TABLE")
try:
    mm = query("model_metrics", "*", "&order=timestamp.desc&limit=5")
    print(f"  Rows: {len(mm)}")
    if mm: print("  Columns:", list(mm[0].keys()))
    for r in mm[:2]: print(f"  {r}")
except Exception as e: print(f"  EMPTY or ERROR: {e}")

# Bug 12 — blocklist_cache
print(SEP, "\nBLOCKLIST_CACHE")
try:
    bl = query("blocklist_cache", "*")
    print(f"  Total: {len(bl)}")
    if bl: print("  Columns:", list(bl[0].keys()))
    for r in bl[:5]: print(f"  {r}")
except Exception as e: print(f"  ERROR: {e}")

# Chatbot — audit_log investigation entries
print(SEP, "\nAUDIT_LOG — investigation_agent rows (first 3)")
try:
    au = query("audit_log", "*", "&agent=eq.investigation_agent&limit=3")
    print(f"  Rows: {len(au)}")
    if au: print("  Columns:", list(au[0].keys()))
    for r in au[:2]:
        print(f"  action={r.get('action')}, reasoning={str(r.get('reasoning',''))[:120]}")
        m = r.get('metadata') or {}
        if isinstance(m, dict): print(f"  metadata keys: {list(m.keys())}")
except Exception as e: print(f"  ERROR: {e}")

# knowledge ingest: check rag source files
print(SEP, "\nCHECK knowledge_ingest.py sources")
import re
with open(r'c:\csPR\ids_lab\rag\knowledge_ingest.py') as f:
    content = f.read()
# Find which tables/sources are ingested
tables_found = re.findall(r'\.table\([\'"](.*?)[\'"]\)', content)
print("Tables ingested:", list(set(tables_found)))
# Count document functions
doc_fns = re.findall(r'def (fetch_|_fetch|ingest_|_ingest).*?\(', content)
print("Ingest functions:", doc_fns)

print("\nDONE")
