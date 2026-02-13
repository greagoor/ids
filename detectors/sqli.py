import re
import urllib.parse
import html

SQL_KEYWORD_PATTERNS = [
    r"\bunion\b\s+\bselect\b",
    r"\bselect\b.+\bfrom\b",
    r"\binsert\b\s+\binto\b",
    r"\bupdate\b.+\bset\b",
    r"\bdelete\b\s+\bfrom\b",
    r"\bdrop\b\s+\btable\b",
    r"\balter\b\s+\btable\b",
    r"\bcreate\b\s+\btable\b",
    r"\bexec\b",
    r"\bexecute\b"
]

SQL_LOGIC_PATTERNS = [
    r"\bor\b\s+\d+\s*=\s*\d+",
    r"\band\b\s+\d+\s*=\s*\d+",
    r"'\s*or\s*'.*?'='",
    r"'\s*--",
    r"--\s*$",
    r"#\s*$"
]

SQL_TIME_PATTERNS = [
    r"\bsleep\s*\(",
    r"\bbenchmark\s*\(",
    r"\bwaitfor\s+delay\b"
]

SQL_ERROR_PATTERNS = [
    r"information_schema",
    r"@@version",
    r"database\(",
    r"user\(",
    r"version\(",
    r"load_file\s*\("
]

STACKED_QUERY = [
    r";\s*(select|insert|update|delete|drop|exec)"
]

def normalize(uri: str):
    decoded = uri
    for _ in range(5):
        decoded = urllib.parse.unquote(decoded)
    decoded = html.unescape(decoded)
    decoded = decoded.replace("\x00", "")
    decoded = re.sub(r"/\*.*?\*/", "", decoded, flags=re.DOTALL)
    return decoded.lower()

def detect(decoded_uri: str):
    indicators = []

    decoded = normalize(decoded_uri)

    for pattern in SQL_KEYWORD_PATTERNS:
        if re.search(pattern, decoded):
            indicators.append("keyword_sql")

    for pattern in SQL_LOGIC_PATTERNS:
        if re.search(pattern, decoded):
            indicators.append("logic_bypass")

    for pattern in SQL_TIME_PATTERNS:
        if re.search(pattern, decoded):
            indicators.append("time_based_sqli")

    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, decoded):
            indicators.append("error_based_sqli")

    for pattern in STACKED_QUERY:
        if re.search(pattern, decoded):
            indicators.append("stacked_query")

    if decoded.count("'") >= 2:
        indicators.append("quote_injection")

    return bool(indicators), indicators
