"""
core/severity.py — Severity calculation from confidence + outcome

Used by detection_agent to map confidence score → severity string.
"""

def severity_from_confidence(confidence: float, outcome: str = "ATTEMPT") -> str:
    """
    Map a numeric confidence (0–100) and HTTP outcome to a severity label.

    Thresholds:
      CRITICAL  → confidence >= 85 AND LIKELY_SUCCESSFUL
      HIGH      → confidence >= 70
      MEDIUM    → confidence >= 40
      LOW       → below 40
    """
    if outcome == "LIKELY_SUCCESSFUL" and confidence >= 85:
        return "CRITICAL"
    if confidence >= 70:
        return "HIGH"
    if confidence >= 40:
        return "MEDIUM"
    return "LOW"
