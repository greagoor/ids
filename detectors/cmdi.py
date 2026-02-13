import re
import urllib.parse
import html

CMD_SEPARATORS = [
    r";",
    r"\|\|",
    r"&&",
    r"\|",
    r"&"
]

COMMON_COMMANDS = [
    r"\bwhoami\b",
    r"\bid\b",
    r"\bls\b",
    r"\bcat\b",
    r"\bpwd\b",
    r"\buname\b",
    r"\bnetstat\b",
    r"\bifconfig\b",
    r"\bping\b",
    r"\bnc\b",
    r"\bwget\b",
    r"\bcurl\b",
    r"\bpython\b",
    r"\bperl\b",
    r"\bbash\b",
    r"\bsh\b",
    r"\bcmd\b",
    r"\bdir\b",
    r"\btype\b"
]

SUBSHELL_PATTERNS = [
    r"`.+?`",
    r"\$\(.+?\)",
    r"\${.+?}"
]

REDIRECTION_PATTERNS = [
    r">\s*/",
    r"2>&1",
    r">>",
]

def normalize(uri: str):
    decoded = uri
    for _ in range(5):
        decoded = urllib.parse.unquote(decoded)
    decoded = html.unescape(decoded)
    decoded = decoded.replace("\x00", "")
    return decoded.lower()

def detect(decoded_uri: str):
    indicators = []

    decoded = normalize(decoded_uri)

    # Subshell execution
    for p in SUBSHELL_PATTERNS:
        if re.search(p, decoded):
            indicators.append("command_execution")
            break

    # Separator + command detection
    for sep in CMD_SEPARATORS:
        if re.search(sep, decoded):
            for cmd in COMMON_COMMANDS:
                if re.search(cmd, decoded):
                    indicators.append("command_execution")
                    break

    # Redirection-based abuse
    for p in REDIRECTION_PATTERNS:
        if re.search(p, decoded):
            indicators.append("command_execution")
            break

    return bool(indicators), indicators
