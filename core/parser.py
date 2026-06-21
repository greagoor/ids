import re

def parse_line(line: str):
    """
    Parses a single tshark line.
    Expected fields:
    ip.src, http.method, http.request.full_uri, http.response.code
    """
    # Split ONLY on tabs, ignore backslashes. strip('\n\r') instead of strip() to keep leading/trailing spaces if any
    parts = line.rstrip('\n\r').split('\t')

    if len(parts) < 3:
        return None

    return {
        "src_ip": parts[0],
        "method": parts[1],
        "uri": parts[2],
        "response_code": parts[3] if len(parts) > 3 else ""
    }
