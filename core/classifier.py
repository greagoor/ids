def classify_outcome(response_code: str) -> str:
    """
    Classify attack outcome based on HTTP response.
    """
    if response_code in ["200", "500"]:
        return "LIKELY_SUCCESSFUL"
    return "ATTEMPT"
