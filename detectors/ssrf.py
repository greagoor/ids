import re

SSRF_PARAMS = [
    "url=", "uri=", "dest=", "redirect=", "next=",
    "callback=", "fetch=", "image="
]

INTERNAL_TARGETS = [
    r"127\.0\.0\.1",
    r"localhost",
    r"169\.254\.169\.254",
    r"10\.",
    r"192\.168\.",
    r"172\.(1[6-9]|2\d|3[0-1])\."
]

def detect(decoded_uri: str):
    indicators = []

    # SSRF only makes sense if a URL-like parameter exists
    if not any(p in decoded_uri for p in SSRF_PARAMS):
        return False, []

    for t in INTERNAL_TARGETS:
        if re.search(t, decoded_uri):
            indicators.append("internal_resource")
            return True, indicators

    return False, []
