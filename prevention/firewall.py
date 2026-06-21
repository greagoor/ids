"""
prevention/firewall.py — Platform-aware firewall action layer

On Linux:  attempts real iptables commands.
On Windows: logs and records mock actions — NEVER touches the OS firewall.

Also enforces blast-radius rate limiting and refuses to block protected
IP ranges (RFC1918, loopback, multicast, Cloudflare CDN).

All actions are logged to audit_log regardless of platform.
"""

import ipaddress
import logging
import os
import platform
import subprocess
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

logger = logging.getLogger(__name__)

IS_LINUX = platform.system() == "Linux"

# ── Protected ranges (never block these) ─────────────────────────────────────
_PROTECTED_NETWORKS = [
    # RFC 1918 private
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Link-local / APIPA
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # Multicast
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    # Cloudflare CDN (minimum set)
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("131.0.72.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
]


def _is_protected(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PROTECTED_NETWORKS)
    except ValueError:
        return False   # Not a parseable IP — allow the action to proceed


# ── Rate limiter ──────────────────────────────────────────────────────────────

class ResponseRateLimiter:
    """
    Blast-radius rate limiter for block actions.
    Prevents the response agent from mass-blocking IPs on a false-positive wave.
    """

    def __init__(
        self,
        max_per_minute: int = int(os.getenv("BLAST_RADIUS_MAX_BLOCKS_PER_MINUTE", "5")),
        max_per_hour:   int = int(os.getenv("BLAST_RADIUS_MAX_BLOCKS_PER_HOUR",   "30")),
    ):
        self.max_per_minute = max_per_minute
        self.max_per_hour   = max_per_hour
        self._minute_window: deque = deque()   # epoch timestamps
        self._hour_window:   deque = deque()
        self._lock = Lock()

    def can_block(self) -> bool:
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            # Prune stale entries
            while self._minute_window and self._minute_window[0] < now - 60:
                self._minute_window.popleft()
            while self._hour_window and self._hour_window[0] < now - 3600:
                self._hour_window.popleft()
            return (
                len(self._minute_window) < self.max_per_minute
                and len(self._hour_window) < self.max_per_hour
            )

    def record_block(self) -> None:
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            self._minute_window.append(now)
            self._hour_window.append(now)

    def stats(self) -> dict:
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            m = sum(1 for t in self._minute_window if t >= now - 60)
            h = sum(1 for t in self._hour_window   if t >= now - 3600)
        return {"blocks_last_minute": m, "blocks_last_hour": h,
                "max_per_minute": self.max_per_minute, "max_per_hour": self.max_per_hour}


# Module-level singleton used by response_agent
_rate_limiter = ResponseRateLimiter()


# ── Firewall actions ──────────────────────────────────────────────────────────

def block_ip(ip: str, alert_id: Optional[str] = None, reason: str = "") -> dict:
    """
    Block an IP via iptables (Linux) or mock log (Windows/other).
    Refuses to block protected ranges on any platform.

    Returns a result dict with: action, ip, platform, mock, success, message.
    """
    if _is_protected(ip):
        msg = f"BLOCK_REFUSED_PROTECTED_RANGE: {ip} is in a protected range."
        logger.warning(msg)
        _write_audit("BLOCK_REFUSED", ip, msg, alert_id)
        return {"action": "BLOCK_REFUSED", "ip": ip, "mock": True,
                "success": False, "message": msg, "platform": platform.system()}

    if IS_LINUX:
        result = _iptables_block(ip)
    else:
        result = _mock_block(ip, reason)

    _write_audit(result["action"], ip, result["message"], alert_id)
    return result


def rate_limit_ip(ip: str, alert_id: Optional[str] = None, reason: str = "") -> dict:
    """
    Rate-limit an IP (token-bucket via iptables on Linux, mock on Windows).
    """
    if _is_protected(ip):
        msg = f"RATE_LIMIT_REFUSED_PROTECTED_RANGE: {ip}"
        logger.warning(msg)
        _write_audit("RATE_LIMIT_REFUSED", ip, msg, alert_id)
        return {"action": "RATE_LIMIT_REFUSED", "ip": ip, "mock": True,
                "success": False, "message": msg, "platform": platform.system()}

    if IS_LINUX:
        result = _iptables_rate_limit(ip)
    else:
        result = _mock_rate_limit(ip, reason)

    _write_audit(result["action"], ip, result["message"], alert_id)
    return result


def unblock_ip(ip: str) -> dict:
    """Remove an IP block (Linux only; mock on Windows)."""
    if IS_LINUX:
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=5
            )
            return {"action": "UNBLOCK", "ip": ip, "mock": False, "success": True,
                    "message": f"iptables: unblocked {ip}"}
        except Exception as e:
            return {"action": "UNBLOCK", "ip": ip, "mock": False, "success": False,
                    "message": str(e)}
    else:
        msg = f"[MOCK] Would unblock {ip} via iptables on Linux."
        logger.info(msg)
        return {"action": "UNBLOCK_MOCK", "ip": ip, "mock": True, "success": True,
                "message": msg}


# ── Platform-specific implementations ────────────────────────────────────────

def _iptables_block(ip: str) -> dict:
    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True, timeout=5
        )
        msg = f"iptables: blocked {ip} (DROP)"
        logger.warning("[FIREWALL] %s", msg)
        return {"action": "BLOCK", "ip": ip, "mock": False, "success": True,
                "message": msg, "platform": "Linux"}
    except Exception as e:
        msg = f"iptables block failed for {ip}: {e}"
        logger.error("[FIREWALL] %s", msg)
        return {"action": "BLOCK_FAILED", "ip": ip, "mock": False, "success": False,
                "message": msg, "platform": "Linux"}


def _iptables_rate_limit(ip: str) -> dict:
    try:
        # 20 packets/min limit via hashlimit
        subprocess.run(
            ["iptables", "-I", "INPUT", "1", "-s", ip,
             "-m", "limit", "--limit", "20/min", "-j", "ACCEPT"],
            check=True, capture_output=True, timeout=5
        )
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True, timeout=5
        )
        msg = f"iptables: rate-limited {ip} to 20 req/min"
        logger.warning("[FIREWALL] %s", msg)
        return {"action": "RATE_LIMIT", "ip": ip, "mock": False, "success": True,
                "message": msg, "platform": "Linux"}
    except Exception as e:
        msg = f"iptables rate-limit failed for {ip}: {e}"
        logger.error("[FIREWALL] %s", msg)
        return {"action": "RATE_LIMIT_FAILED", "ip": ip, "mock": False, "success": False,
                "message": msg, "platform": "Linux"}


def _mock_block(ip: str, reason: str) -> dict:
    msg = (
        f"[MOCK BLOCK] IP {ip} would be blocked via iptables on Linux. "
        f"Reason: {reason or 'threat_score > 80'}. "
        f"Running on Windows — action logged only."
    )
    logger.warning("[FIREWALL MOCK] %s", msg)
    return {"action": "BLOCK_MOCK", "ip": ip, "mock": True, "success": True,
            "message": msg, "platform": "Windows"}


def _mock_rate_limit(ip: str, reason: str) -> dict:
    msg = (
        f"[MOCK RATE-LIMIT] IP {ip} would be rate-limited via iptables on Linux. "
        f"Reason: {reason or 'threat_score 50-80'}. "
        f"Running on Windows — action logged only."
    )
    logger.warning("[FIREWALL MOCK] %s", msg)
    return {"action": "RATE_LIMIT_MOCK", "ip": ip, "mock": True, "success": True,
            "message": msg, "platform": "Windows"}


# ── Audit helper ──────────────────────────────────────────────────────────────

def _write_audit(action: str, ip: str, message: str, alert_id: Optional[str]) -> None:
    try:
        from cloud_db import write_audit_log
        write_audit_log(
            agent     = "firewall",
            action    = action,
            reasoning = message,
            metadata  = {"ip": ip, "platform": platform.system(), "mock": not IS_LINUX},
            alert_id  = alert_id,
        )
    except Exception as e:
        logger.error("Failed to write firewall audit log: %s", e)


# ── Public rate limiter accessor ──────────────────────────────────────────────

def get_rate_limiter() -> ResponseRateLimiter:
    return _rate_limiter
