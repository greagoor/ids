import sys
import urllib.parse
import re
import json
from datetime import datetime, timezone
from cloud_db import save_alert, upsert_incident


# ---------- SQLi RULES ----------
SQL_KEYWORDS = [
    "union select",
    "select from",
    "insert into",
    "drop table"
]

SQL_LOGIC_PATTERNS = [
    r"\bor\b\s*1\s*=\s*1",
    r"\band\b\s*1\s*=\s*1",
    r"or\s*1\s*=\s*1",
    r"and\s*1\s*=\s*1"
]

# ---------- XSS RULES ----------
XSS_PATTERNS = [
    r"<\s*script",
    r"</\s*script",
    r"alert\s*\(",
    r"onerror\s*=",
    r"onload\s*=",
    r"<\s*img"
]

# ---------- COMMAND INJECTION RULES ----------
CMD_INJECTION_PATTERNS = [
    r";\s*(ls|id|whoami|cat)",
    r"\|\s*(ls|id|whoami|cat)",
    r"&&\s*(ls|id|whoami|cat)",
    r"`.+?`"
]

# ---------- LFI RULES ----------
LFI_PATTERNS = [
    r"\.\./\.\./",
    r"\.\.\\\.\.\\",
    r"/etc/passwd",
    r"/etc/shadow",
    r"boot\.ini",
    r"windows/system32"
]


def detect_sqli(decoded_uri):
    return (
        any(k in decoded_uri for k in SQL_KEYWORDS) or
        any(re.search(p, decoded_uri) for p in SQL_LOGIC_PATTERNS)
    )


def detect_xss(decoded_uri):
    return any(re.search(p, decoded_uri) for p in XSS_PATTERNS)


def detect_cmd_injection(decoded_uri):
    return any(re.search(p, decoded_uri) for p in CMD_INJECTION_PATTERNS)


def detect_lfi(decoded_uri):
    return any(re.search(p, decoded_uri) for p in LFI_PATTERNS)


def classify_attack(response_code):
    if response_code in ["200", "500"]:
        return "LIKELY_SUCCESSFUL"
    return "ATTEMPT"


def get_confidence(attack_type, decoded_uri):
    if attack_type == "SQL_INJECTION":
        return 90 if "union select" in decoded_uri else 75
    if attack_type == "XSS":
        return 85
    if attack_type == "COMMAND_INJECTION":
        return 90
    if attack_type == "LFI":
        return 80
    return 50


# ---------- MAIN PIPELINE ----------
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue

    parts = re.split(r"[\t\\]", line)
    if len(parts) < 3:
        continue

    src_ip = parts[0]
    method = parts[1]
    full_uri = parts[2]
    response_code = parts[3] if len(parts) > 3 else ""

    decoded = urllib.parse.unquote(full_uri).lower()
    outcome = classify_attack(response_code)

    attack_type = None
    if detect_sqli(decoded):
        attack_type = "SQL_INJECTION"
    elif detect_xss(decoded):
        attack_type = "XSS"
    elif detect_cmd_injection(decoded):
        attack_type = "COMMAND_INJECTION"
    elif detect_lfi(decoded):
        attack_type = "LFI"
    else:
        continue

    now = datetime.now(timezone.utc)
    confidence = get_confidence(attack_type, decoded)

    alert = {
        "timestamp": now.isoformat(),
        "attack_type": attack_type,
        "outcome": outcome,
        "confidence": confidence,
        "src_ip": src_ip,
        "method": method,
        "uri": full_uri
    }

    print(json.dumps(alert, indent=2))
    save_alert(alert)
    upsert_incident(alert)
