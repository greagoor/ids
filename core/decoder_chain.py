"""
core/decoder_chain.py — Multi-layer payload decoder

Iteratively applies up to 5 passes or until output stabilises:
  1. URL-decode (%xx)
  2. HTML-entity decode (&amp;, &#x41;, etc.)
  3. Unicode confusable normalisation (NFKC)
  4. Hex-escape decode (\\xNN)
  5. Best-effort Base64 detection/decode for long printable chunks

Returns:
    {
        "original":       <str>,
        "decoded":        <str>,
        "depth":          <int>,   # decode passes applied
        "layers_applied": <list>,  # names of transforms used
        "was_obfuscated": <bool>,  # True if any layer changed the string
    }
"""

import base64
import binascii
import html
import re
import unicodedata
import urllib.parse
import logging

logger = logging.getLogger(__name__)

MAX_PASSES = 5

# ── Individual decode layers ──────────────────────────────────────────────────

def _url_decode(s: str) -> tuple[str, bool]:
    try:
        decoded = urllib.parse.unquote(s)
        return decoded, decoded != s
    except Exception:
        return s, False


def _html_entity_decode(s: str) -> tuple[str, bool]:
    decoded = html.unescape(s)
    return decoded, decoded != s


def _unicode_normalise(s: str) -> tuple[str, bool]:
    """NFKC collapses visually similar characters to their canonical form."""
    normalised = unicodedata.normalize("NFKC", s)
    return normalised, normalised != s


def _hex_escape_decode(s: str) -> tuple[str, bool]:
    """Decode \\xNN hex escape sequences."""
    pattern = re.compile(r'\\x([0-9a-fA-F]{2})')
    changed = [False]

    def replace(m):
        changed[0] = True
        return chr(int(m.group(1), 16))

    decoded = pattern.sub(replace, s)
    return decoded, changed[0]


def _base64_decode_chunks(s: str) -> tuple[str, bool]:
    """
    Find long printable Base64-looking chunks (≥20 chars) and attempt to decode.
    Only replaces the chunk if the decoded result is printable ASCII — avoids
    false positives on random strings that happen to be valid B64.
    """
    # Matches standard and URL-safe Base64 chunks
    pattern = re.compile(r'(?:[A-Za-z0-9+/\-_]{20,}={0,2})')
    changed = [False]

    def try_decode(m):
        chunk = m.group(0)
        # Pad to multiple of 4
        padded = chunk + '=' * ((-len(chunk)) % 4)
        # Try both standard and URL-safe
        for variant in (padded, padded.replace('-', '+').replace('_', '/')):
            try:
                decoded_bytes = base64.b64decode(variant)
                decoded_str = decoded_bytes.decode('utf-8')
                # Only accept if >60% printable (rejects binary blobs)
                printable = sum(c.isprintable() for c in decoded_str)
                if printable / max(len(decoded_str), 1) > 0.6:
                    changed[0] = True
                    return decoded_str
            except (binascii.Error, UnicodeDecodeError):
                continue
        return chunk

    result = pattern.sub(try_decode, s)
    return result, changed[0]


# ── Layer registry (applied in order) ────────────────────────────────────────

_LAYERS = [
    ("url_decode",       _url_decode),
    ("html_entity",      _html_entity_decode),
    ("unicode_nfkc",     _unicode_normalise),
    ("hex_escape",       _hex_escape_decode),
    ("base64_chunks",    _base64_decode_chunks),
]


# ── Main entry point ──────────────────────────────────────────────────────────

def decode_payload(raw: str) -> dict:
    """
    Multi-layer decode of a URL/payload string.

    Returns a dict with keys: original, decoded, depth, layers_applied,
    was_obfuscated.
    """
    if not raw:
        return {
            "original":       raw,
            "decoded":        raw,
            "depth":          0,
            "layers_applied": [],
            "was_obfuscated": False,
        }

    current         = raw
    depth           = 0
    layers_applied  = []

    for _pass in range(MAX_PASSES):
        pass_changed = False

        for layer_name, layer_fn in _LAYERS:
            result, changed = layer_fn(current)
            if changed:
                current      = result
                pass_changed = True
                if layer_name not in layers_applied:
                    layers_applied.append(layer_name)

        if pass_changed:
            depth += 1
        else:
            # Stable — no more decoding possible
            break

    return {
        "original":       raw,
        "decoded":        current,
        "depth":          depth,
        "layers_applied": layers_applied,
        "was_obfuscated": len(layers_applied) > 0,
    }


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    samples = [
        # 1. Double URL-encoded SQLi
        "id%253D1%2520UNION%2520SELECT%2520username%252Cpassword%2520FROM%2520users",
        # 2. HTML-entity encoded XSS
        "&lt;script&gt;alert(document.cookie)&lt;/script&gt;",
        # 3. Hex-escape obfuscated CMDi
        "\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64",
        # 4. Base64-encoded LFI
        "Li4vLi4vLi4vZXRjL3Bhc3N3ZA==",
        # 5. Unicode confusable + URL-encoded XSS
        "%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%281%29%3C%2F%73%63%72%69%70%74%3E",
    ]

    print("\n── decoder_chain self-test ──\n")
    for s in samples:
        result = decode_payload(s)
        print(f"Input:    {s[:70]}")
        print(f"Decoded:  {result['decoded'][:70]}")
        print(f"Depth:    {result['depth']}  |  Layers: {result['layers_applied']}")
        print(f"Obfusc:   {result['was_obfuscated']}")
        print()
