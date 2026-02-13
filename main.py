import sys

from utils.decoding import decode_uri
from core.parser import parse_line
from core.classifier import classify_outcome
from core.alert_builder import build_alert
from output.stdout import emit
from output.database import persist
from cloud_db import expire_old_incidents

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


def expiry_loop():
    while True:
        expire_old_incidents()
        decay_incident_severity()
        time.sleep(60)


threading.Thread(target=expiry_loop, daemon=True).start()


# SQL detector commented for ML demo
DETECTORS = [
    ("COMMAND_INJECTION", cmdi.detect),
    # ("SQL_INJECTION", sqli.detect),
    ("XSS", xss.detect),
    ("LFI", lfi.detect),
    ("PATH_TRAVERSAL", path_traversal.detect),
    ("RFI", rfi.detect),
    ("SSRF", ssrf.detect)
]


for line in sys.stdin:

    parsed = parse_line(line)
    if not parsed:
        continue

    decoded = decode_uri(parsed["uri"])

    print("RAW URI:", parsed["uri"])
    print("DECODED URI:", decoded)

    outcome = classify_outcome(parsed["response_code"])

    # ----------------------------
    # 1️⃣ RULE DETECTION FIRST
    # ----------------------------
    rule_detected = False
    final_attack = None
    final_indicators = []

    for attack_type, detector in DETECTORS:
        detected, indicators = detector(decoded)
        print("Checking:", attack_type, "→", detected)

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

        ml_result = predict(http_obj)

        print("ML Result:", ml_result)

        if ml_result["attack_confidence"] >= 50:
            final_attack = ATTACK_LABELS[ml_result["attack_type"]]
            final_indicators = ["ml_detected"]

    # If still nothing detected → skip
    if not final_attack:
        continue

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
