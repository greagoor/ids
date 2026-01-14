from urllib.parse import unquote

# Base severity per attack type
BASE_SCORES = {
    "SSRF": 50,
    "RFI": 40,
    "PATH_TRAVERSAL": 35,
    "LFI": 35,
    "COMMAND_INJECTION": 45,
    "SQL_INJECTION": 40,
    "XSS": 30,
}

# Indicator weights
INDICATOR_WEIGHTS = {
    "internal_resource": 40,
    "remote_file_include": 30,
    "directory_traversal": 25,
    "local_file_access": 25,
    "command_execution": 35,
    "logic_bypass": 30,
    "keyword_sql": 25,
    "xss_pattern": 20,
}

def encoding_depth(uri: str) -> int:
    """
    Detects multiple URL decoding layers.
    """
    depth = 0
    current = uri
    while "%" in current:
        decoded = unquote(current)
        if decoded == current:
            break
        depth += 1
        current = decoded
    return depth


def response_weight(response_code: str) -> int:
    if not response_code:
        return 0
    if response_code.startswith("2"):
        return 20
    if response_code.startswith("3"):
        return 10
    if response_code.startswith("5"):
        return 15
    return 0


def calculate_confidence(
    *,
    attack_type: str,
    indicators: list,
    uri: str,
    response_code: str
):
    score = BASE_SCORES.get(attack_type, 30)

    breakdown = {
        "base": score,
        "indicators": 0,
        "encoding": 0,
        "response": 0,
    }

    # Indicator contribution
    for ind in indicators:
        breakdown["indicators"] += INDICATOR_WEIGHTS.get(ind, 10)

    # Encoding depth (evasion awareness)
    depth = encoding_depth(uri)
    breakdown["encoding"] = min(depth * 10, 20)

    # Response contribution
    breakdown["response"] = response_weight(response_code)

    score = sum(breakdown.values())
    score = min(score, 100)

    return score, breakdown
