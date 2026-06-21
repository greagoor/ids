"""
intel/mitre_mapper.py — MITRE ATT&CK technique mapper

Loads enterprise-attack.json ONCE at import time from the project root.
Exposes map_attack_to_technique(attack_type) -> list[dict] with:
  - technique_id (e.g. T1190)
  - name
  - description (truncated to 300 chars from the JSON)

The 7 attack types map to:
  SQL_INJECTION  → T1190  (Exploit Public-Facing Application)
  XSS            → T1059.007 (JavaScript - Command & Scripting Interpreter)
  LFI            → T1083  (File and Directory Discovery)
  PATH_TRAVERSAL → T1083  (File and Directory Discovery)
  RFI            → T1105  (Ingress Tool Transfer)
  SSRF           → T1090  (Proxy - Connection Proxy)
  COMMAND_INJECTION → T1059 (Command and Scripting Interpreter)
"""

import json
import logging
import os
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)

# Hardcoded mapping: attack_type → MITRE technique IDs
_ATTACK_TO_TECHNIQUE_IDS: dict[str, list[str]] = {
    "SQL_INJECTION":      ["T1190"],
    "XSS":                ["T1059.007"],
    "LFI":                ["T1083"],
    "PATH_TRAVERSAL":     ["T1083", "T1006"],
    "RFI":                ["T1105"],
    "SSRF":               ["T1090"],
    "COMMAND_INJECTION":  ["T1059"],
}

# Technique ID → human name (fallback if JSON lookup fails)
_TECHNIQUE_NAMES: dict[str, str] = {
    "T1190":     "Exploit Public-Facing Application",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1059":     "Command and Scripting Interpreter",
    "T1083":     "File and Directory Discovery",
    "T1006":     "Direct Volume Access",
    "T1105":     "Ingress Tool Transfer",
    "T1090":     "Proxy",
}

# ── Load enterprise-attack.json once ─────────────────────────────────────────

_MITRE_DB: dict[str, dict] = {}   # technique_id → {name, description}

def _load_mitre_json() -> None:
    """Parse enterprise-attack.json and index techniques by external ID."""
    json_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "enterprise-attack.json"
    )
    if not os.path.exists(json_path):
        logger.warning("enterprise-attack.json not found at %s — using fallback names only.", json_path)
        return

    try:
        logger.info("Loading enterprise-attack.json (53 MB) — may take a moment...")
        with open(json_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            ext_refs = obj.get("external_references", [])
            tech_id = None
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id")
                    break
            if not tech_id:
                continue

            _MITRE_DB[tech_id] = {
                "name":        obj.get("name", _TECHNIQUE_NAMES.get(tech_id, "Unknown")),
                "description": (obj.get("description") or "")[:300],
                "kill_chain":  [
                    phase.get("phase_name", "")
                    for phase in obj.get("kill_chain_phases", [])
                ],
            }

        logger.info("MITRE DB loaded: %d techniques indexed.", len(_MITRE_DB))
    except Exception as e:
        logger.error("Failed to load enterprise-attack.json: %s — using fallback names.", e)


# Load at import time (module-level side effect, happens once)
_load_mitre_json()


# ── Public API ────────────────────────────────────────────────────────────────

def map_attack_to_technique(attack_type: str) -> list[dict]:
    """
    Return MITRE technique info for the given attack type.

    Returns list of dicts:
        [{"technique_id": "T1190", "name": "...", "description": "..."}]
    Returns empty list for unknown attack types.
    """
    tech_ids = _ATTACK_TO_TECHNIQUE_IDS.get(attack_type.upper(), [])
    results = []
    for tid in tech_ids:
        if tid in _MITRE_DB:
            entry = _MITRE_DB[tid]
            results.append({
                "technique_id": tid,
                "name":         entry["name"],
                "description":  entry["description"],
                "kill_chain":   entry.get("kill_chain", []),
            })
        else:
            # Fallback to hardcoded name
            results.append({
                "technique_id": tid,
                "name":         _TECHNIQUE_NAMES.get(tid, "Unknown Technique"),
                "description":  "",
                "kill_chain":   [],
            })
    return results


def get_all_technique_ids() -> list[str]:
    """Return all technique IDs mapped by this system (for MITRE heatmap)."""
    ids = set()
    for v in _ATTACK_TO_TECHNIQUE_IDS.values():
        ids.update(v)
    return sorted(ids)


if __name__ == "__main__":
    for attack in _ATTACK_TO_TECHNIQUE_IDS:
        techniques = map_attack_to_technique(attack)
        print(f"\n{attack}:")
        for t in techniques:
            print(f"  {t['technique_id']} — {t['name']}")
            if t['description']:
                print(f"    {t['description'][:100]}...")
