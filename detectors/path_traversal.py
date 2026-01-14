import re

TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e%5c"
]

def detect(decoded_uri: str):
    indicators = []

    for p in TRAVERSAL_PATTERNS:
        if re.search(p, decoded_uri):
            indicators.append("directory_traversal")
            break

    return bool(indicators), indicators
