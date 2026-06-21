"""
api/main.py — FastAPI backend for the Agentic IDS Platform

Endpoints:
  GET  /api/alerts          — recent alerts (REST fallback for Realtime)
  GET  /api/incidents       — active incidents
  GET  /api/agent-status    — all agent heartbeats
  GET  /api/audit-log       — recent audit log entries
  GET  /api/system-health   — latest system health
  POST /api/chat            — RAG chatbot
  POST /api/feedback        — analyst TP/FP feedback
  POST /api/demo/simulate   — trigger attack simulation
  GET  /demo/target         — safe sandbox echo endpoint (simulation target)
  GET  /api/ingest-now      — on-demand knowledge base refresh

Honeypot routes mounted from prevention/honeypot.py
CORS configured for Vite dev server (localhost:5173)
"""

import logging
import os
import random
import time
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

load_dotenv()
logger = logging.getLogger(__name__)

# ── App init ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "Agentic IDS Platform API",
    description = "Backend API for the multi-agent cyber defense platform",
    version     = "2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Mount honeypot router ─────────────────────────────────────────────────────
from prevention.honeypot import router as honeypot_router
app.include_router(honeypot_router)


# ── Startup check ─────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup_event():
    try:
        from cloud_db import _db
        _db().table("agent_status").select("agent_name").limit(1).execute()
        print("\n[OK] Supabase connectivity verified.\n")
    except Exception as e:
        print(f"\n[FAIL] Supabase connectivity FAILED: {e}")
        print("   Ensure SUPABASE_URL and SUPABASE_KEY are set in .env\n")


# ── Request/response models ───────────────────────────────────────────────────

class ChatRequest(BaseModel):
    query:        str
    analyst_role: str = "junior"

class FeedbackRequest(BaseModel):
    alert_id: Optional[str] = None
    analyst:  str           = "anonymous"
    verdict:  str           = "UNSURE"   # TP / FP / UNSURE
    notes:    Optional[str] = None

class SimulateRequest(BaseModel):
    attack_type: str   # sqli | xss | cmdi | lfi | rfi | ssrf | path_traversal


# ── Read endpoints ────────────────────────────────────────────────────────────

@app.get("/api/alerts")
async def get_alerts(limit: int = 50, offset: int = 0):
    try:
        from cloud_db import _db
        res = (
            _db()
            .table("alerts")
            .select("*")
            .order("timestamp", desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )
        return {"data": res.data or [], "count": len(res.data or [])}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/incidents")
async def get_incidents(status: Optional[str] = None, limit: int = 50):
    try:
        from cloud_db import _db
        query = _db().table("incidents").select("*").order("last_seen", desc=True).limit(limit)
        if status:
            query = query.eq("status", status)
        res = query.execute()
        return {"data": res.data or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/agent-status")
async def get_agent_status():
    try:
        from cloud_db import _db
        res = _db().table("agent_status").select("*").execute()
        return {"data": res.data or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit-log")
async def get_audit_log(limit: int = 100, agent: Optional[str] = None):
    try:
        from cloud_db import _db
        query = _db().table("audit_log").select("*").order("timestamp", desc=True).limit(limit)
        if agent:
            query = query.eq("agent", agent)
        res = query.execute()
        return {"data": res.data or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/system-health")
async def get_system_health():
    try:
        from cloud_db import _db
        res = (
            _db()
            .table("system_health")
            .select("*")
            .order("timestamp", desc=True)
            .limit(10)
            .execute()
        )
        return {"data": res.data or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/model-metrics")
async def get_model_metrics(limit: int = 30):
    try:
        from cloud_db import _db
        res = (
            _db()
            .table("model_metrics")
            .select("*")
            .order("timestamp", desc=True)
            .limit(limit)
            .execute()
        )
        return {"data": res.data or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/honeypot-logs")
async def get_honeypot_logs(limit: int = 100):
    try:
        from cloud_db import _db
        res = (
            _db()
            .table("honeypot_logs")
            .select("*")
            .order("timestamp", desc=True)
            .limit(limit)
            .execute()
        )
        return {"data": res.data or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/blocklist")
async def get_blocklist():
    try:
        from cloud_db import _db
        now = datetime.now(timezone.utc).isoformat()
        res = (
            _db()
            .table("blocklist_cache")
            .select("*")
            .gt("blocked_until", now)
            .execute()
        )
        return {"data": res.data or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Chat endpoint ─────────────────────────────────────────────────────────────

@app.post("/api/chat")
async def chat(req: ChatRequest):
    try:
        from rag.chatbot import answer_query
        result = await answer_query(req.query, analyst_role=req.analyst_role)
        return result
    except Exception as e:
        logger.error("/api/chat error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


# ── Feedback endpoint ─────────────────────────────────────────────────────────

@app.post("/api/feedback")
async def submit_feedback(req: FeedbackRequest):
    try:
        from cloud_db import _db
        row = {
            "analyst":   req.analyst,
            "verdict":   req.verdict.upper(),
            "notes":     req.notes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if req.alert_id:
            row["alert_id"] = req.alert_id
        _db().table("feedback").insert(row).execute()
        return {"status": "ok", "message": "Feedback recorded."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Knowledge ingest on-demand ────────────────────────────────────────────────

@app.get("/api/ingest-now")
async def ingest_now():
    try:
        import asyncio
        from rag.knowledge_ingest import run_full_ingest
        result = await asyncio.to_thread(run_full_ingest)
        return {"status": "ok", "results": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Demo mode ─────────────────────────────────────────────────────────────────

@app.get("/demo/target")
@app.post("/demo/target")
async def demo_target(request: Request):
    """
    Safe sandbox echo endpoint — accepts anything, logs it, executes nothing.
    Attack simulators send requests here, which flow into detection_agent.
    """
    params  = dict(request.query_params)
    try:
        body = await request.body()
        body_str = body.decode("utf-8", errors="replace")
    except Exception:
        body_str = ""

    # Support X-Forwarded-For for accurate simulation/spoofing
    ip     = request.headers.get("X-Forwarded-For", request.client.host if request.client else "127.0.0.1")
    method = request.method
    url    = str(request.url)

    logger.info("[demo/target] %s %s from %s | params=%s", method, url, ip, params)

    # Run through detection agent (non-blocking)
    try:
        from agents.detection_agent import run_detection
        import asyncio
        asyncio.create_task(
            asyncio.to_thread(
                run_detection,
                ip           = ip,
                method       = method,
                url          = url,
                response_code = "200",
                raw_payload  = body_str or str(params),
                outcome      = "LIKELY_SUCCESSFUL",
                source       = "demo",
            )
        )
    except Exception as e:
        logger.error("[demo/target] detection error: %s", e)

    return JSONResponse({
        "status":  "received",
        "method":  method,
        "params":  params,
        "body":    body_str[:200] if body_str else "",
        "note":    "This is a safe sandbox endpoint. No execution occurs.",
    })


@app.post("/api/demo/simulate")
async def simulate_attack(req: SimulateRequest):
    """
    Trigger an attack simulation from the React dashboard.
    Generates a realistic payload and sends it to /demo/target,
    which flows into the full agent pipeline.
    """
    try:
        from tools.attack_generator import generate_attack
        import httpx
        import asyncio

        attack_type = req.attack_type.lower()
        payload_url, payload_body = generate_attack(attack_type)

        base = "http://127.0.0.1:8000"
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{base}/demo/target", params={"q": payload_url})

        return {
            "status":      "simulated",
            "attack_type": attack_type,
            "payload_sent": payload_url[:200],
            "demo_target_status": resp.status_code,
            "message":     "Attack simulation sent to pipeline. Watch Agent Timeline.",
        }
    except Exception as e:
        logger.error("/api/demo/simulate error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
