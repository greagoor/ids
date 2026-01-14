import re

XSS_PATTERNS = [
    r"<\s*script",
    r"</\s*script",
    r"alert\s*\(",
    r"onerror\s*=",
    r"onload\s*=",
    r"<\s*img"
]

def detect(decoded_uri: str):
    indicators = []

    for p in XSS_PATTERNS:
        if re.search(p, decoded_uri):
            indicators.append("xss_pattern")
            break

    return bool(indicators), indicators
