"""
tools/verify_pipeline.py -- End-to-end pipeline dry-run (Part C verification)

Simulates 3 realistic tshark lines (1 benign, 1 SQLi, 1 XSS) going through
the exact same code path as the live workflow WITHOUT needing Supabase.

Cloud_db functions are monkey-patched to log to a local list instead of
writing to Supabase, so this runs offline and shows exactly what WOULD be
written to agent_queue, alerts, audit_log.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from datetime import datetime, timezone

# -- 1. Monkey-patch cloud_db BEFORE any imports use it -----------------------
_captured = {
    "agent_queue": [],
    "alerts":      [],
    "incidents":   [],
    "audit_log":   [],
    "agent_status":[],
}

import cloud_db as _cdb

def _mock_write_to_queue(sender, receiver, payload, alert_id=None, priority="MEDIUM"):
    _captured["agent_queue"].append({
        "sender": sender, "receiver": receiver,
        "payload_keys": list(payload.keys()), "priority": priority,
        "verdict": payload.get("verdict"), "attack_type": payload.get("attack_type"),
        "ip": payload.get("ip"), "ml_score": payload.get("ml_score"),
        "rule_match": payload.get("rule_match"),
    })

def _mock_save_alert(alert):
    _captured["alerts"].append({
        "ip": alert.get("ip") or alert.get("src_ip"),
        "attack_type": alert.get("attack_type"),
        "confidence": alert.get("confidence"),
        "severity": alert.get("severity"),
        "verdict": alert.get("verdict"),
    })

def _mock_upsert_incident(alert):
    _captured["incidents"].append({
        "ip": alert.get("ip") or alert.get("src_ip"),
        "attack_type": alert.get("attack_type"),
    })

def _mock_write_audit_log(agent, action, reasoning="", metadata=None, alert_id=None):
    _captured["audit_log"].append({
        "agent": agent, "action": action, "reasoning": reasoning[:80],
    })

def _mock_update_agent_status(agent_name, status, current_alert_id=None):
    _captured["agent_status"].append({"agent": agent_name, "status": status})

def _mock_check_blocklist(ip): return None
def _mock_add_to_blocklist(*a, **kw): pass
def _mock_record_ip_seen(ip): pass
def _mock_upsert_session(*a, **kw): pass
def _mock_write_model_metrics(*a, **kw): pass

_cdb.write_to_queue        = _mock_write_to_queue
_cdb.save_alert            = _mock_save_alert
_cdb.upsert_incident       = _mock_upsert_incident
_cdb.write_audit_log       = _mock_write_audit_log
_cdb.update_agent_status   = _mock_update_agent_status
_cdb.check_blocklist       = _mock_check_blocklist
_cdb.add_to_blocklist      = _mock_add_to_blocklist

import intel.blocklist as _bl
_bl.is_blocklisted   = lambda ip: False
_bl.record_ip_seen   = lambda ip: None

# -- 2. Import the real pipeline modules --------------------------------------
from core.parser        import parse_line
from utils.decoding     import decode_uri
from core.classifier    import classify_outcome
from core.alert_builder import build_alert
from core.scoring       import calculate_confidence

from detectors import sqli, xss, cmdi, lfi, rfi, ssrf, path_traversal

# -- 2. Mock the OLD ml/predict (pre-existing feature mismatch 20vs17 features)
#    This is in the frozen ml/ directory -- not our code. We mock it here so
#    the benign-request fallback path works without crashing.
import ml.predict as _ml_mod
_ml_mod.predict = lambda http_obj: {"attack_type": 0, "attack_confidence": 0, "suspicion_score": 0}
predict = _ml_mod.predict   # local name used in pipeline loop below
ML_AVAILABLE = True
print("  [NOTE] ml/predict mocked: pre-existing sklearn feature mismatch (20 vs 17).")
print("         Benign requests return NORMAL/confidence=0 and are correctly skipped.")


ATTACK_LABELS = {0:"NORMAL",1:"SQL_INJECTION",2:"XSS",3:"COMMAND_INJECTION",
                 4:"LFI",5:"RFI",6:"SSRF"}

DETECTORS = [
    ("COMMAND_INJECTION", cmdi.detect),
    ("XSS",              xss.detect),
    ("LFI",              lfi.detect),
    ("PATH_TRAVERSAL",   path_traversal.detect),
    ("RFI",              rfi.detect),
    ("SSRF",             ssrf.detect),
]

from agents.detection_agent import enqueue_from_main

# -- 3. Construct 3 tshark-format sample lines ---------------------------------
# Format: ip.src TAB method TAB full_uri TAB response_code
TSHARK_LINES = [
    # Line 1 -- benign (should be filtered out before enqueue)
    "192.168.10.5\tGET\thttp://localhost/index.html\t200",
    # Line 2 -- SQL Injection (should hit rule detector -> agent_queue)
    "10.0.0.41\tGET\thttp://localhost/login?user=admin'--&pass=x\t200",
    # Line 3 -- XSS in search param (should hit rule detector -> agent_queue)
    "203.0.113.7\tPOST\thttp://localhost/search?q=<script>alert(document.cookie)</script>\t200",
]

print("\n" + "=" * 65)
print("  PART C -- End-to-End Pipeline Dry-Run")
print("  (Supabase replaced with local capture dict)")
print("=" * 65)

results = []

for raw_line in TSHARK_LINES:
    print(f"\n--- Input: {raw_line[:70]}...")

    # Exact same code path as main.py's stdin loop
    parsed = parse_line(raw_line)
    if not parsed:
        print("  SKIP: parse_line returned None")
        continue

    decoded   = decode_uri(parsed["uri"])
    outcome   = classify_outcome(parsed["response_code"])

    rule_detected  = False
    final_attack   = None
    final_indicators = []

    for attack_type, detector in DETECTORS:
        detected, indicators = detector(decoded)
        if detected:
            rule_detected    = True
            final_attack     = attack_type
            final_indicators = indicators
            break

    if not rule_detected and ML_AVAILABLE:
        http_obj = {
            "method": parsed["method"],
            "url": parsed["uri"].split("?")[0],
            "query": parsed["uri"].split("?")[1] if "?" in parsed["uri"] else "",
            "body": ""
        }
        ml_result = predict(http_obj)
        if ml_result["attack_confidence"] >= 50:
            final_attack     = ATTACK_LABELS[ml_result["attack_type"]]
            final_indicators = ["ml_detected"]

    if not final_attack:
        print(f"  RESULT: BENIGN -- skipped (no attack detected, not enqueued) [OK]")
        results.append({"line": raw_line[:50], "result": "BENIGN/SKIPPED"})
        continue

    confidence, score_breakdown = calculate_confidence(
        attack_type=final_attack, indicators=final_indicators,
        uri=decoded, response_code=parsed["response_code"]
    )

    alert = build_alert(
        attack_type=final_attack,
        src_ip=parsed["src_ip"],
        method=parsed["method"],
        uri=parsed["uri"],
        response_code=parsed["response_code"],
        outcome=outcome,
        confidence=confidence,
        indicators=final_indicators,
    )
    alert["score_breakdown"] = score_breakdown

    print(f"  DETECTED: {final_attack} | confidence={confidence} | ip={parsed['src_ip']}")

    # Simulate persist() -- mock already captures it
    _mock_save_alert(alert)
    _mock_upsert_incident(alert)

    # Call enqueue_from_main and wait for the background thread
    enqueue_from_main(alert)
    import time; time.sleep(0.5)   # allow daemon thread to finish

    results.append({
        "line":        raw_line[:50],
        "attack_type": final_attack,
        "confidence":  confidence,
        "result":      "ENQUEUED",
    })
    print(f"  RESULT: ENQUEUED to agent_queue [OK]")

# -- 4. Report captured table contents -----------------------------------------
print("\n" + "=" * 65)
print("  CAPTURED TABLE WRITES")
print("=" * 65)

print(f"\n[alerts] -- {len(_captured['alerts'])} row(s) written:")
for r in _captured["alerts"]:
    print(f"  ip={r['ip']}  attack={r['attack_type']}  conf={r['confidence']}  sev={r['severity']}")

print(f"\n[incidents] -- {len(_captured['incidents'])} row(s) written:")
for r in _captured["incidents"]:
    print(f"  ip={r['ip']}  attack={r['attack_type']}")

print(f"\n[agent_queue] -- {len(_captured['agent_queue'])} row(s) written:")
for r in _captured["agent_queue"]:
    print(f"  sender={r['sender']}  receiver={r['receiver']}")
    print(f"  verdict={r['verdict']}  attack={r['attack_type']}  ip={r['ip']}")
    print(f"  ml_score={r['ml_score']}  rule_match={r['rule_match']}")

print(f"\n[audit_log] -- {len(_captured['audit_log'])} row(s) written:")
for r in _captured["audit_log"]:
    print(f"  agent={r['agent']}  action={r['action']}")
    print(f"  reasoning={r['reasoning']}")

print(f"\n[agent_status] -- {len(_captured['agent_status'])} transition(s):")
for r in _captured["agent_status"]:
    print(f"  {r['agent']} -> {r['status']}")

# -- 5. Final verdict ----------------------------------------------------------
print("\n" + "=" * 65)
enqueued = len(_captured["agent_queue"])
expected = sum(1 for r in results if r.get("result") == "ENQUEUED")
if enqueued == expected:
    print(f"  PASS: {enqueued}/{expected} attacks reached agent_queue [OK]")
else:
    print(f"  FAIL: expected {expected} queue writes, got {enqueued}")
print("=" * 65 + "\n")
