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

import time
last_expiry_check = 0

import threading

def expiry_loop():
    while True:
        expire_old_incidents()
        decay_incident_severity()
        time.sleep(60)


threading.Thread(target=expiry_loop, daemon=True).start()


DETECTORS = [
    ("SSRF", ssrf.detect),
    ("RFI", rfi.detect),
    ("PATH_TRAVERSAL", path_traversal.detect),
    ("LFI", lfi.detect),
    ("COMMAND_INJECTION", cmdi.detect),
    ("SQL_INJECTION", sqli.detect),
    ("XSS", xss.detect),
]

for line in sys.stdin:
        
    parsed = parse_line(line)
    if not parsed:
        continue

    decoded = decode_uri(parsed["uri"])
    outcome = classify_outcome(parsed["response_code"])

    for attack_type, detector in DETECTORS:
        detected, indicators = detector(decoded)

        if detected:
            confidence, score_breakdown = calculate_confidence(
                attack_type=attack_type,
                indicators=indicators,
                uri=decoded,
                response_code=parsed["response_code"]
            )

            alert = build_alert(
                attack_type=attack_type,
                src_ip=parsed["src_ip"],
                method=parsed["method"],
                uri=parsed["uri"],
                response_code=parsed["response_code"],
                outcome=outcome,
                confidence=confidence,
                indicators=indicators
            )

            alert["score_breakdown"] = score_breakdown
            

            emit(alert)
            persist(alert)

            break
    
