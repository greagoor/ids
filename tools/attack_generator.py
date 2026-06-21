"""
tools/attack_generator.py — Attack simulation orchestrator

generate_attack(attack_type) -> (url_payload, body_payload)

Dispatches to the appropriate per-type module.
Used by /api/demo/simulate FastAPI endpoint.
"""

import random
from typing import Tuple


def generate_attack(attack_type: str) -> Tuple[str, str]:
    """
    Generate a realistic attack payload for the given attack type.

    Args:
        attack_type: One of sqli, xss, cmdi, lfi, rfi, ssrf,
                     path_traversal (case-insensitive)

    Returns:
        (url_with_payload, raw_payload_string)
    """
    key = attack_type.lower().strip().replace("-", "_").replace(" ", "_")

    if key in ("sqli", "sql_injection", "sql"):
        from tools.sqli_atk import generate
    elif key in ("xss", "cross_site_scripting"):
        from tools.xss_atk import generate
    elif key in ("cmdi", "cmdi_injection", "command_injection", "rce"):
        from tools.cmdi_atk import generate
    elif key in ("lfi", "local_file_inclusion"):
        from tools.lfi_atk import generate
    elif key in ("rfi", "remote_file_inclusion"):
        from tools.rfi_atk import generate
    elif key in ("ssrf", "server_side_request_forgery"):
        from tools.ssrf_atk import generate
    elif key in ("path_traversal", "patht", "traversal", "directory_traversal"):
        from tools.pathT_atk import generate
    else:
        raise ValueError(
            f"Unknown attack type: '{attack_type}'. "
            f"Valid types: sqli, xss, cmdi, lfi, rfi, ssrf, path_traversal"
        )

    return generate()


def random_attack() -> Tuple[str, str, str]:
    """Return (attack_type, url, body) for a randomly chosen attack type."""
    attack_types = ["sqli", "xss", "cmdi", "lfi", "rfi", "ssrf", "path_traversal"]
    chosen = random.choice(attack_types)
    url, body = generate_attack(chosen)
    return chosen, url, body


if __name__ == "__main__":
    """Quick self-test — generate one payload per attack type."""
    types = ["sqli", "xss", "cmdi", "lfi", "rfi", "ssrf", "path_traversal"]
    print("\n── Attack Generator Self-Test ──\n")
    for t in types:
        url, body = generate_attack(t)
        print(f"{t:20s} → {url[:90]}")
    print()
