import sys

from utils.decoding import decode_uri
from core.parser import parse_line
from core.classifier import classify_outcome
from core.alert_builder import build_alert
from output.stdout import emit
from output.database import persist
from cloud_db import expire_old_incidents
from agents.detection_agent import enqueue_from_main  # additive agent wiring

from core.scoring import calculate_confidence

from cloud_db import expire_old_incidents, decay_incident_severity

from detectors import (
    sqli, xss, cmdi, lfi,
    rfi, ssrf, path_traversal
)

from ml.predict import predict

ATTACK_LABELS = {
    0: "NORMAL",
    1: "SQL_INJECTION",
    2: "XSS",
    3: "COMMAND_INJECTION",
    4: "LFI",
    5: "RFI",
    6: "SSRF"
}

import time
import threading


from cloud_db import update_agent_status

def expiry_loop():
    # Initial startup heartbeat
    try:
        update_agent_status("detection_agent", "IDLE")
    except Exception:
        pass
        
    while True:
        expire_old_incidents()
        decay_incident_severity()
        try:
            update_agent_status("detection_agent", "IDLE")
        except Exception:
            pass
        time.sleep(60)

threading.Thread(target=expiry_loop, daemon=True).start()

print(
    "[main.py] Bridged to agent_queue — new agent system will process alerts if running.",
    flush=True,
)


# All rule detectors active — sqli previously commented for ML demo, now restored
DETECTORS = [
    ("SQL_INJECTION",    sqli.detect),
    ("COMMAND_INJECTION", cmdi.detect),
    ("XSS",              xss.detect),
    ("LFI",              lfi.detect),
    ("PATH_TRAVERSAL",   path_traversal.detect),
    ("RFI",              rfi.detect),
    ("SSRF",             ssrf.detect)
]


for line in sys.stdin:

    parsed = parse_line(line)
    if not parsed:
        continue

    decoded = decode_uri(parsed["uri"])
    outcome = classify_outcome(parsed["response_code"])

    # ----------------------------
    # 1️⃣ RULE DETECTION FIRST
    # ----------------------------
    rule_detected = False
    final_attack = None
    final_indicators = []

    for attack_type, detector in DETECTORS:
        detected, indicators = detector(decoded)
        if detected:
            rule_detected = True
            final_attack = attack_type
            final_indicators = indicators
            break

    # ----------------------------
    # 2️⃣ ML FALLBACK IF RULE MISSED
    # ----------------------------
    if not rule_detected:
        http_obj = {
            "method": parsed["method"],
            "url": parsed["uri"].split("?")[0],
            "query": parsed["uri"].split("?")[1] if "?" in parsed["uri"] else "",
            "body": ""
        }
        try:
            ml_result = predict(http_obj)
            if ml_result["attack_confidence"] >= 50:
                final_attack = ATTACK_LABELS[ml_result["attack_type"]]
                final_indicators = ["ml_detected"]
        except Exception:
            # Old ml/predict feature mismatch. Skip silently.
            pass

    # If still nothing detected → skip
    if not final_attack:
        continue
        
    print(f"[main.py] Alert detected via {final_attack}! Queueing to Agent System...", flush=True)

    # ----------------------------
    # 3️⃣ CONTINUE EXISTING PIPELINE
    # ----------------------------
    confidence, score_breakdown = calculate_confidence(
        attack_type=final_attack,
        indicators=final_indicators,
        uri=decoded,
        response_code=parsed["response_code"]
    )

    alert = build_alert(
        attack_type=final_attack,
        src_ip=parsed["src_ip"],
        method=parsed["method"],
        uri=parsed["uri"],
        response_code=parsed["response_code"],
        outcome=outcome,
        confidence=confidence,
        indicators=final_indicators
    )

    alert["score_breakdown"] = score_breakdown

    emit(alert)
    persist(alert)
    try:
        enqueue_from_main(alert)  # additive: push into agent pipeline (non-blocking)
    except Exception as _e:
        import logging as _log
        _log.getLogger(__name__).warning(
            "[main.py] enqueue_from_main failed (agent system may be offline): %s", _e
        )
