import re

LFI_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"/etc/passwd",
    r"/etc/shadow",
    r"boot\.ini",
    r"windows/system32"
]

def detect(decoded_uri: str):
    indicators = []

    for p in LFI_PATTERNS:
        if re.search(p, decoded_uri):
            indicators.append("local_file_access")
            break

    return bool(indicators), indicators
