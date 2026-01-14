import re

SQL_KEYWORDS = [
    "union select",
    "select from",
    "insert into",
    "drop table"
]

SQL_LOGIC_PATTERNS = [
    r"\bor\b\s*1\s*=\s*1",
    r"\band\b\s*1\s*=\s*1"
]

def detect(decoded_uri: str):
    indicators = []

    if any(k in decoded_uri for k in SQL_KEYWORDS):
        indicators.append("keyword_sql")

    if any(re.search(p, decoded_uri) for p in SQL_LOGIC_PATTERNS):
        indicators.append("logic_bypass")

    return bool(indicators), indicators
