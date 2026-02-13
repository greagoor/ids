import re
from urllib.parse import urlparse, parse_qs

SSRF_PARAMS = [
    "url", "uri", "dest", "redirect", "next",
    "callback", "fetch", "image"
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

    parsed = urlparse(decoded_uri)
    query_params = parse_qs(parsed.query)

    for param in SSRF_PARAMS:
        if param in query_params:
            values = query_params[param]
            for value in values:
                for t in INTERNAL_TARGETS:
                    if re.search(t, value):
                        indicators.append("internal_resource")
                        return True, indicators

    return False, []
