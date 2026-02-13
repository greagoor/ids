# ids/ml/feature_extractor.py

import re
from urllib.parse import unquote

# --- keyword banks (shared across attacks, NOT rules) ---

SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete",
    "drop", "sleep", "benchmark", "or", "and"
]

XSS_KEYWORDS = [
    "<script", "javascript:", "onerror", "onload", "alert("
]

CMD_KEYWORDS = [
    "cmd", "bash", "powershell", "sh", "exec"
]

FILE_KEYWORDS = [
    "../", "..\\", "/etc/", "boot.ini", "windows/system32"
]

SSRF_KEYWORDS = [
    "http://", "https://", "127.0.0.1", "localhost", "169.254"
]


# --- helpers ---

def count_keywords(text, keywords):
    text = text.lower()
    return sum(text.count(k) for k in keywords)


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
    xss_kw = count_keywords(decoded_payload, XSS_KEYWORDS)
    cmd_kw = count_keywords(decoded_payload, CMD_KEYWORDS)
    file_kw = count_keywords(decoded_payload, FILE_KEYWORDS)
    ssrf_kw = count_keywords(decoded_payload, SSRF_KEYWORDS)

    # --- context ---
    http_method = 0 if method == "GET" else 1 if method == "POST" else 2
    has_body = int(bool(body))

    return [
        url_length,
        query_length,
        body_length,
        num_params,
        num_slashes,
        num_dots,
        num_digits,
        num_encoded_chars,
        num_special_chars,
        double_encoded,
        sql_kw,
        xss_kw,
        cmd_kw,
        file_kw,
        ssrf_kw,
        http_method,
        has_body
    ]

