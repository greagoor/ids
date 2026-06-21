# ids/ml/feature_extractor.py

import re
from urllib.parse import unquote

# --- keyword banks (shared across attacks, NOT rules) ---

SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete",
    "drop", "sleep", "benchmark", "waitfor", "extractvalue"
]

# SQL boolean operators — matched as whole words to avoid substring FPs
SQL_BOOL_OPERATORS = [r"\bor\b", r"\band\b"]

XSS_KEYWORDS = [
    "<script", "javascript:", "onerror", "onload", "alert(",
    "<svg", "<img", "<iframe", "<body"
]

# CMDI: match actual payload content (shell commands / operators)
CMD_KEYWORDS = [
    "whoami", "passwd", "/etc/passwd", "id &&", "ls;",
    "`", "$(", "cat ", "ping ", "curl ", "wget "
]
CMD_OPERATORS = [";", "&&", "||", "|", "`", "$("]

FILE_KEYWORDS = [
    "../", "..\\", "/etc/", "boot.ini", "windows/system32"
]

# SSRF: internal-address focused (no generic http/https)
SSRF_KEYWORDS = [
    "127.0.0.1", "localhost", "169.254", "0.0.0.0", "::1",
    "internal", "metadata", "meta-data"
]

# RFI: external domain / remote file patterns
RFI_KEYWORDS = [
    "http://", "https://",
    ".php", ".txt", ".sh", ".asp",
    "shell", "backdoor", "payload", "evil", "malicious", "attacker"
]


# --- helpers ---

def count_keywords(text, keywords):
    text = text.lower()
    return sum(text.count(k) for k in keywords)


def count_regex_keywords(text, patterns):
    """Count whole-word or regex keyword matches to avoid substring FPs."""
    text = text.lower()
    return sum(len(re.findall(p, text)) for p in patterns)


def has_double_encoding(text):
    return int("%25" in text.lower())


# --- MAIN FEATURE FUNCTION ---

def extract_features(http):
    """
    Input: parsed HTTP request (dict)
    Output: list of numeric features (ordered)
    """

    method = http.get("method", "").upper()
    url = http.get("url", "") or ""
    query = http.get("query", "") or ""
    body = http.get("body", "") or ""

    full_payload = f"{url} {query} {body}"
    decoded_payload = unquote(full_payload)

    # --- structural ---
    url_length = len(url)
    query_length = len(query)
    body_length = len(body)

    num_params = query.count("&") + 1 if query else 0
    num_slashes = full_payload.count("/") + full_payload.count("\\")
    num_dots = full_payload.count(".")
    num_digits = sum(c.isdigit() for c in full_payload)

    # --- encoding / obfuscation ---
    num_encoded_chars = len(re.findall(r"%[0-9a-fA-F]{2}", full_payload))
    num_special_chars = len(re.findall(r"[<>'\";()]", full_payload))
    double_encoded = has_double_encoding(full_payload)

    # --- keyword densities ---
    sql_kw = count_keywords(decoded_payload, SQL_KEYWORDS)
    sql_bool_kw = count_regex_keywords(decoded_payload, SQL_BOOL_OPERATORS)
    xss_kw = count_keywords(decoded_payload, XSS_KEYWORDS)
    cmd_kw = count_keywords(decoded_payload, CMD_KEYWORDS)
    cmd_op_kw = count_keywords(decoded_payload, CMD_OPERATORS)
    file_kw = count_keywords(decoded_payload, FILE_KEYWORDS)
    ssrf_kw = count_keywords(decoded_payload, SSRF_KEYWORDS)
    rfi_kw = count_keywords(decoded_payload, RFI_KEYWORDS)

    # --- context ---
    http_method = 0 if method == "GET" else 1 if method == "POST" else 2
    has_body = int(bool(body))

    return [
        url_length,          # 0
        query_length,        # 1
        body_length,         # 2
        num_params,          # 3
        num_slashes,         # 4
        num_dots,            # 5
        num_digits,          # 6
        num_encoded_chars,   # 7
        num_special_chars,   # 8
        double_encoded,      # 9
        sql_kw,              # 10
        sql_bool_kw,         # 11  <-- NEW: replaces ambiguous 'or'/'and' count
        xss_kw,              # 12
        cmd_kw,              # 13
        cmd_op_kw,           # 14  <-- NEW: shell operator count
        file_kw,             # 15
        ssrf_kw,             # 16
        rfi_kw,              # 17  <-- NEW: replaces generic ssrf for RFI
        http_method,         # 18
        has_body             # 19
    ]

