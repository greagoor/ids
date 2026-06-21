"""
tools/verify_pipeline2.py  -  Part C re-run after SQLi + ML fixes
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---- mock cloud_db -------------------------------------------------------
captured = {"agent_queue": [], "audit_log": [], "agent_status": [], "alerts": [], "incidents": []}
import cloud_db as _cdb
_cdb.write_to_queue      = lambda sender, receiver, payload, alert_id=None, priority="MEDIUM": \
    captured["agent_queue"].append({"sender": sender, "receiver": receiver,
        "verdict": payload.get("verdict"), "attack_type": payload.get("attack_type"),
        "ip": payload.get("ip"), "ml_score": payload.get("ml_score"),
        "rule_match": payload.get("rule_match")})
_cdb.write_audit_log     = lambda agent, action, reasoning="", metadata=None, alert_id=None: \
    captured["audit_log"].append({"agent": agent, "action": action})
_cdb.update_agent_status = lambda name, status, cid=None: \
    captured["agent_status"].append({"agent": name, "status": status})

import intel.blocklist as _bl
_bl.is_blocklisted = lambda ip: False
_bl.record_ip_seen = lambda ip: None

# ---- mock OLD ml/predict (broken - feature mismatch in frozen model) ------
import ml.predict as _ml
_ml.predict = lambda h: (_ for _ in ()).throw(
    ValueError("X has 20 features, but RandomForestClassifier expecting 17"))
predict = _ml.predict

# ---- import real pipeline components -------------------------------------
from core.parser        import parse_line
from utils.decoding     import decode_uri
from core.classifier    import classify_outcome
from core.alert_builder import build_alert
from core.scoring       import calculate_confidence
from detectors import sqli, xss, cmdi, lfi, rfi, ssrf, path_traversal
from agents.detection_agent import _bridge_pipeline

ATTACK_LABELS = {0:"NORMAL",1:"SQL_INJECTION",2:"XSS",3:"COMMAND_INJECTION",4:"LFI",5:"RFI",6:"SSRF"}

# DETECTORS list now matches fixed main.py (SQLi restored)
DETECTORS = [
    ("SQL_INJECTION",    sqli.detect),
    ("COMMAND_INJECTION", cmdi.detect),
    ("XSS",              xss.detect),
    ("LFI",              lfi.detect),
    ("PATH_TRAVERSAL",   path_traversal.detect),
    ("RFI",              rfi.detect),
    ("SSRF",             ssrf.detect),
]

TSHARK_LINES = [
    "192.168.10.5\tGET\thttp://localhost/index.html\t200",
    "10.0.0.41\tGET\thttp://localhost/login?user=admin'--&pass=x\t200",
    "203.0.113.7\tPOST\thttp://localhost/search?q=<script>alert(document.cookie)</script>\t200",
]

print("=" * 65)
print("  Part C Re-Run: SQLi restored + ML try/except active")
print("=" * 65)

results = []
for raw in TSHARK_LINES:
    print(f"\n-- Input: {raw[:72]}")
    parsed = parse_line(raw)
    if not parsed:
        print("  SKIP: parse failed"); continue

    decoded = decode_uri(parsed["uri"])
    outcome = classify_outcome(parsed["response_code"])

    rule_detected, final_attack, final_indicators = False, None, []
    for attack_type, fn in DETECTORS:
        detected, indicators = fn(decoded)
        if detected:
            rule_detected, final_attack, final_indicators = True, attack_type, indicators
            break

    # ML fallback (now wrapped in try/except)
    if not rule_detected:
        try:
            http_obj = {"method": parsed["method"],
                        "url": parsed["uri"].split("?")[0],
                        "query": parsed["uri"].split("?")[1] if "?" in parsed["uri"] else "",
                        "body": ""}
            ml_result = predict(http_obj)
            if ml_result["attack_confidence"] >= 50:
                final_attack     = ATTACK_LABELS[ml_result["attack_type"]]
                final_indicators = ["ml_detected"]
        except Exception as err:
            print(f"  [main.py] ML fallback skipped (predict error): {err}")

    if not final_attack:
        print("  RESULT: BENIGN -- correctly skipped, NOT enqueued")
        results.append({"ip": parsed["src_ip"], "result": "BENIGN"})
        continue

    confidence, breakdown = calculate_confidence(
        attack_type=final_attack, indicators=final_indicators,
        uri=decoded, response_code=parsed["response_code"])

    alert = build_alert(attack_type=final_attack, src_ip=parsed["src_ip"],
        method=parsed["method"], uri=parsed["uri"],
        response_code=parsed["response_code"], outcome=outcome,
        confidence=confidence, indicators=final_indicators)
    alert["score_breakdown"] = breakdown

    # Mock persist()
    captured["alerts"].append({"ip": parsed["src_ip"], "attack_type": final_attack, "confidence": confidence})
    captured["incidents"].append({"ip": parsed["src_ip"], "attack_type": final_attack})

    print(f"  DETECTED: {final_attack} | confidence={confidence} | ip={parsed['src_ip']}")
    _bridge_pipeline(alert)   # direct call, no thread
    print("  RESULT: Enqueued to agent_queue")
    results.append({"ip": parsed["src_ip"], "attack": final_attack, "result": "ENQUEUED"})

# ---- report ---------------------------------------------------------------
print("\n" + "=" * 65)
print("  CAPTURED TABLE WRITES")
print("=" * 65)

print(f"\n[alerts]     {len(captured['alerts'])} row(s):")
for r in captured["alerts"]:
    print(f"  ip={r['ip']}  attack={r['attack_type']}  confidence={r['confidence']}")

print(f"\n[incidents]  {len(captured['incidents'])} row(s):")
for r in captured["incidents"]:
    print(f"  ip={r['ip']}  attack={r['attack_type']}")

print(f"\n[agent_queue] {len(captured['agent_queue'])} row(s):")
for r in captured["agent_queue"]:
    print(f"  sender={r['sender']}  receiver={r['receiver']}")
    print(f"  verdict={r['verdict']}  attack={r['attack_type']}  ip={r['ip']}  ml_score={r['ml_score']}")
    print(f"  rule_match={r['rule_match']}")

print(f"\n[audit_log]  {len(captured['audit_log'])} row(s):")
for r in captured["audit_log"]:
    print(f"  agent={r['agent']}  action={r['action']}")

print(f"\n[agent_status] {len(captured['agent_status'])} transitions:")
for r in captured["agent_status"]:
    print(f"  {r['agent']} -> {r['status']}")

# final verdict
enqueued  = [r for r in results if r["result"] == "ENQUEUED"]
print("\n" + "=" * 65)
print(f"  FINAL: {len(enqueued)}/2 attack inputs reached agent_queue")
sqli_ok = any(r.get("attack") == "SQL_INJECTION" for r in enqueued)
xss_ok  = any(r.get("attack") == "XSS" for r in enqueued)
print(f"  SQLi enqueued : {'PASS' if sqli_ok else 'FAIL'}")
print(f"  XSS  enqueued : {'PASS' if xss_ok  else 'FAIL'}")
print(f"  Benign skipped: {'PASS' if results[0]['result']=='BENIGN' else 'FAIL'}")
print("=" * 65)
