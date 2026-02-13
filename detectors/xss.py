import re
import urllib.parse
import html

XSS_PATTERNS = [
    r"<\s*/?\s*script\b[^>]*>",
    r"\bon\w+\s*=\s*['\"]?",
    r"j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:",
    r"<\s*(img|svg|iframe|body|embed|object|link|style|video|audio|base)\b",
    r"\b(alert|prompt|confirm|eval|expression|settimeout|setinterval)\s*\(",
    r"(document\.cookie|document\.write|window\.location)",
    r"data\s*:\s*text\/html",
    r"fromcharcode\s*\(",
    r"constructor\s*\(",
    r"%3c",
    r"%3e",
    r"&#x3c;",
    r"&#x3e;"
]

def detect(uri: str):
    indicators = []

    decoded = uri

    # deeper decoding
    for _ in range(5):
        decoded = urllib.parse.unquote(decoded)

    decoded = html.unescape(decoded)
    decoded = decoded.replace("\x00", "")
    decoded = decoded.lower()

    # remove JS comments
    decoded = re.sub(r"/\*.*?\*/", "", decoded, flags=re.DOTALL)

    for pattern in XSS_PATTERNS:
        if re.search(pattern, decoded, re.IGNORECASE):
            indicators.append("xss_pattern")

    # small heuristic improvement
    if decoded.count("<") >= 1 and decoded.count(">") >= 1 and decoded.count("=") >= 1:
        indicators.append("xss_pattern")

    return bool(indicators), indicators
