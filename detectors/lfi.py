import re
import urllib.parse
import html

REMOTE_PROTOCOL = re.compile(r"(http|https|ftp|php|data|expect|phar)://", re.IGNORECASE)

LFI_PATTERNS = [
    r"/etc/passwd",
    r"/etc/shadow",
    r"/proc/self/environ",
    r"/proc/self/cmdline",
    r"/proc/version",
    r"/var/log/",
    r"boot\.ini",
    r"win\.ini",
    r"system32\\drivers\\etc\\hosts",
    r"\.env"
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

    # Extract file parameter value safely
    if "file=" in decoded:
        file_value = decoded.split("file=", 1)[1]
    else:
        file_value = decoded

    # Skip only if the file parameter contains remote protocol
    if REMOTE_PROTOCOL.search(file_value):
        return False, []

    for p in LFI_PATTERNS:
        if re.search(p, decoded):
            indicators.append("local_file_access")
            break

    return bool(indicators), indicators

