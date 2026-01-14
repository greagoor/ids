from datetime import datetime, timezone
from core.severity import severity_from_confidence

def build_alert(
    *,
    attack_type: str,
    src_ip: str,
    method: str,
    uri: str,
    response_code: str,
    outcome: str,
    confidence: int,
    indicators: list
):  
    severity = severity_from_confidence(confidence, outcome)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_type": attack_type,
        "src_ip": src_ip,
        "method": method,
        "uri": uri,
        "response_code": response_code,
        "outcome": outcome,
        "severity": severity,
        "confidence": confidence,
        "indicators": indicators
    }
