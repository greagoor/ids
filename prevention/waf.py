"""
prevention/waf.py — Lightweight inline Web Application Firewall

Reuses the existing frozen detectors/* rule functions rather than
reimplementing pattern matching. Used by FastAPI demo/honeypot endpoints
to pre-screen incoming requests before they reach the agent pipeline.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Frozen detectors (do not modify these imports)
from detectors import sqli, xss, cmdi, lfi, rfi, ssrf, path_traversal

_RULES = [
    ("SQL_INJECTION",    sqli.detect),
    ("XSS",              xss.detect),
    ("COMMAND_INJECTION", cmdi.detect),
    ("LFI",              lfi.detect),
    ("PATH_TRAVERSAL",   path_traversal.detect),
    ("RFI",              rfi.detect),
    ("SSRF",             ssrf.detect),
]


def inspect(
    url:     str,
    payload: str = "",
    method:  str = "GET",
) -> dict:
    """
    Run WAF rule checks against a URL and optional payload string.

    Returns:
        {
            "blocked":      bool,
            "attack_type":  str | None,
            "indicators":   list[str],
            "checked":      ["url", "payload"],
        }
    """
    from core.decoder_chain import decode_payload

    decoded_url     = decode_payload(url)["decoded"]
    decoded_payload = decode_payload(payload)["decoded"] if payload else ""

    # Check URL first, then payload
    for target_str, target_name in [(decoded_url, "url"), (decoded_payload, "payload")]:
        if not target_str:
            continue
        for attack_type, detect_fn in _RULES:
            try:
                detected, indicators = detect_fn(target_str)
                if detected:
                    logger.info(
                        "[WAF] BLOCKED %s in %s → %s",
                        attack_type, target_name, indicators
                    )
                    return {
                        "blocked":     True,
                        "attack_type": attack_type,
                        "indicators":  indicators,
                        "matched_in":  target_name,
                    }
            except Exception as e:
                logger.error("WAF rule %s failed: %s", attack_type, e)

    return {
        "blocked":     False,
        "attack_type": None,
        "indicators":  [],
        "matched_in":  None,
    }


def waf_middleware_check(request_url: str, body: str = "", method: str = "GET") -> Optional[dict]:
    """
    Convenience wrapper: returns the waf result dict if blocked, else None.
    Suitable for use as an early-return check in FastAPI route handlers.
    """
    result = inspect(url=request_url, payload=body, method=method)
    return result if result["blocked"] else None
