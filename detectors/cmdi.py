import re

CMD_PATTERNS = [
    r";\s*(ls|id|whoami|cat)",
    r"\|\s*(ls|id|whoami|cat)",
    r"&&\s*(ls|id|whoami|cat)",
    r"`.+?`"
]

def detect(decoded_uri: str):
    indicators = []

    for p in CMD_PATTERNS:
        if re.search(p, decoded_uri):
            indicators.append("command_execution")
            break

    return bool(indicators), indicators
