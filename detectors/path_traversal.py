import re
import urllib.parse
import html

TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"\.\.%2f",
    r"%2e%2e/",
    r"%2e%2e\\",
    r"%252e%252e",
    r"\.\.%00",
    r"%00",
    r"\.\./\.\./",
    r"\.\.\/",
    r"\.\.\\\\",
    r"\.\.\//"
]

def normalize(uri: str):
    decoded = uri
    for _ in range(5):
        decoded = urllib.parse.unquote(decoded)
    decoded = html.unescape(decoded)
    decoded = decoded.replace("\x00", "")
    return decoded.lower()

def detect(decoded_uri: str):
    indicators = []

    decoded = normalize(decoded_uri)

    for p in TRAVERSAL_PATTERNS:
        if re.search(p, decoded):
            indicators.append("directory_traversal")
            break

    if decoded.count("../") >= 2 or decoded.count("..\\") >= 2:
        indicators.append("directory_traversal")

    return bool(indicators), indicators
