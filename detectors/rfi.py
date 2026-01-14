import re

RFI_PARAMS = [
    "file=", "page=", "include=", "template=", "load=", "path="
]

REMOTE_PROTOCOL = re.compile(r"(http|https|ftp|data|php|expect)://", re.IGNORECASE)

def detect(decoded_uri: str):
    indicators = []

    # RFI only makes sense if a file/include parameter exists
    if not any(p in decoded_uri for p in RFI_PARAMS):
        return False, []

    # Extract parameter values roughly (good enough for IDS)
    for param in RFI_PARAMS:
        if param in decoded_uri:
            value = decoded_uri.split(param, 1)[1]

            # Stop at next parameter if exists
            value = value.split("&")[0]

            if REMOTE_PROTOCOL.search(value):
                indicators.append("remote_file_include")
                return True, indicators

    return False, []
