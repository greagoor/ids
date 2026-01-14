def severity_from_confidence(confidence, outcome):
    if outcome == "LIKELY_SUCCESSFUL":
        if confidence >= 80:
            return "CRITICAL"
        elif confidence >= 70:
            return "HIGH"
        else:
            return "MEDIUM"

    # ATTEMPT
    if confidence >= 60:
        return "HIGH"
    elif confidence >= 30:
        return "MEDIUM"
    else:
        return "LOW"

SEVERITY_MAP = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

def severity_to_int(severity_str: str) -> int:
    return SEVERITY_MAP.get(severity_str, 1)
