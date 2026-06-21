"""
prevention/honeypot.py — FastAPI router for honeypot trap endpoints

Fake endpoints: /admin, /.env, /config.php, /wp-admin, /phpmyadmin
Any hit:
  1. Logs full request to honeypot_logs table
  2. Runs payload through detection_agent for classification
  3. If same IP hits 2+ honeypot endpoints → auto-promote to blocklist_cache
  4. Pushes IP+payload into ChromaDB honeypot_logs collection
"""

import logging
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Request, Response

logger = logging.getLogger(__name__)

router = APIRouter(tags=["honeypot"])

# In-memory: track how many distinct honeypot endpoints each IP has hit
_hp_hit_counts: dict[str, set] = defaultdict(set)

HONEYPOT_ENDPOINTS = ["/admin", "/.env", "/config.php", "/wp-admin", "/phpmyadmin"]


async def _handle_honeypot(request: Request, endpoint: str) -> Response:
    ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")

    # Collect headers and body
    headers = dict(request.headers)
    try:
        body = await request.body()
        payload_str = body.decode("utf-8", errors="replace")[:2000]
    except Exception:
        payload_str = ""

    full_url = str(request.url)
    logger.warning("[honeypot] Hit on %s from %s", endpoint, ip)

    # 1. Log to Supabase honeypot_logs
    try:
        from cloud_db import write_honeypot_log
        write_honeypot_log(ip=ip, endpoint=endpoint, headers=headers, payload=payload_str)
    except Exception as e:
        logger.error("[honeypot] DB log failed: %s", e)

    # 2. Track distinct endpoints hit by this IP
    _hp_hit_counts[ip].add(endpoint)
    distinct_count = len(_hp_hit_counts[ip])

    # 3. Auto-promote to blocklist if 2+ distinct honeypot endpoints hit
    if distinct_count >= 2:
        try:
            from intel.blocklist import add_to_blocklist
            add_to_blocklist(ip, source="honeypot", score=95.0, hours=48)
            logger.warning(
                "[honeypot] IP %s hit %d honeypot endpoints — auto-promoted to blocklist.",
                ip, distinct_count,
            )
        except Exception as e:
            logger.error("[honeypot] blocklist auto-promote failed: %s", e)

    # 4. Run through detection agent (non-blocking)
    try:
        from agents.detection_agent import run_detection
        import asyncio
        asyncio.create_task(asyncio.to_thread(
            run_detection,
            ip=ip,
            method=request.method,
            url=full_url,
            response_code="200",
            raw_payload=payload_str,
            outcome="LIKELY_SUCCESSFUL",
            source="honeypot"
        ))
    except Exception as e:
        logger.error("[honeypot] detection enqueue failed: %s", e)

    # 5. Push into ChromaDB honeypot collection (async, best-effort)
    try:
        from rag.knowledge_ingest import _ingest_honeypot_logs
        import asyncio
        asyncio.create_task(asyncio.to_thread(_ingest_honeypot_logs))
    except Exception:
        pass

    # Return a convincing fake response to keep attacker engaged
    fake_responses = {
        "/admin":       b"<html><body><h1>Admin Panel</h1><p>Loading...</p></body></html>",
        "/.env":        b"APP_KEY=base64:abc123\nDB_PASSWORD=supersecret\n",
        "/config.php":  b"<?php // Configuration loaded ?>",
        "/wp-admin":    b"<html><body><h1>WordPress Admin</h1></body></html>",
        "/phpmyadmin":  b"<html><body><h1>phpMyAdmin</h1></body></html>",
    }
    body_resp = fake_responses.get(endpoint, b"OK")
    return Response(content=body_resp, media_type="text/html", status_code=200)


# Register routes for all honeypot endpoints
@router.api_route("/admin",      methods=["GET", "POST", "PUT", "DELETE"])
async def honeypot_admin(request: Request):
    return await _handle_honeypot(request, "/admin")

@router.api_route("/.env",       methods=["GET", "POST", "PUT", "DELETE"])
async def honeypot_env(request: Request):
    return await _handle_honeypot(request, "/.env")

@router.api_route("/config.php", methods=["GET", "POST", "PUT", "DELETE"])
async def honeypot_config(request: Request):
    return await _handle_honeypot(request, "/config.php")

@router.api_route("/wp-admin",   methods=["GET", "POST", "PUT", "DELETE"])
async def honeypot_wp(request: Request):
    return await _handle_honeypot(request, "/wp-admin")

@router.api_route("/phpmyadmin", methods=["GET", "POST", "PUT", "DELETE"])
async def honeypot_phpmyadmin(request: Request):
    return await _handle_honeypot(request, "/phpmyadmin")
