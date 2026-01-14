import urllib.parse

def decode_uri(uri: str) -> str:
    """
    Safely URL-decode and normalize a URI for detection.
    """
    try:
        return urllib.parse.unquote(uri).lower()
    except Exception:
        return uri.lower()
