"""
run_agents.py — Single-command orchestrator for the entire agent system

Usage:  python run_agents.py

Starts:
  - All agent run_forever() loops as asyncio tasks
  - FastAPI app via uvicorn programmatically (port 8000)
  - Knowledge ingest periodic loop
  - Session tracker write-through flush
  - Blocklist periodic refresh

Run alongside main.py | tshark pipeline in a separate terminal.
"""

import asyncio
import logging
import os
import sys

import uvicorn
from dotenv import load_dotenv

load_dotenv()

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level   = getattr(logging, log_level, logging.INFO),
    format  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers = [logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("run_agents")


async def main():
    logger.info("=" * 60)
    logger.info("  Agentic IDS Platform — Starting Agent System")
    logger.info("=" * 60)

    # ── agent_queue health check ───────────────────────────────────────────────
    try:
        from cloud_db import _db
        res = (
            _db()
            .table("agent_queue")
            .select("created_at, sender, status")
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if rows:
            r = rows[0]
            logger.info(
                "[run_agents.py] Last message in agent_queue: %s  from=%s  status=%s",
                r.get("created_at"), r.get("sender"), r.get("status"),
            )
        else:
            logger.info(
                "[run_agents.py] agent_queue is empty — no traffic received yet."
            )
    except Exception as e:
        logger.warning("[run_agents.py] Could not query agent_queue: %s", e)

    # ── Import all agents ──────────────────────────────────────────────────────
    from agents.pretriage_agent     import run_forever as pretriage_loop
    from agents.investigation_agent import run_forever as investigation_loop
    from agents.response_agent      import run_forever as response_loop
    from agents.learning_agent      import run_forever as learning_loop
    from agents.watchdog_agent      import run_forever as watchdog_loop
    from agents.honeypot_agent      import run_forever as honeypot_loop
    from rag.knowledge_ingest       import run_forever as ingest_loop
    from intel.blocklist            import periodic_blocklist_refresh
    from core.session_tracker       import start_background_flush

    # ── Start FastAPI via uvicorn in a background task ────────────────────────
    config = uvicorn.Config(
        "api.main:app",
        host        = "0.0.0.0",
        port        = 8000,
        log_level   = log_level.lower(),
        reload      = False,
    )
    server = uvicorn.Server(config)

    logger.info("Starting FastAPI server on http://0.0.0.0:8000 ...")

    # ── Create all tasks ───────────────────────────────────────────────────────
    tasks = [
        asyncio.create_task(server.serve(),           name="fastapi_server"),
        asyncio.create_task(pretriage_loop(),         name="pretriage_agent"),
        asyncio.create_task(investigation_loop(),     name="investigation_agent"),
        asyncio.create_task(response_loop(),          name="response_agent"),
        asyncio.create_task(learning_loop(),          name="learning_agent"),
        asyncio.create_task(watchdog_loop(),          name="watchdog_agent"),
        asyncio.create_task(honeypot_loop(),          name="honeypot_agent"),
        asyncio.create_task(ingest_loop(),            name="knowledge_ingest"),
        asyncio.create_task(periodic_blocklist_refresh(), name="blocklist_refresh"),
        asyncio.create_task(start_background_flush(), name="session_flush"),
    ]

    logger.info("All agents started:")
    for t in tasks:
        logger.info("  * %s", t.get_name())

    logger.info("-" * 60)
    logger.info("  React dashboard: npm run dev  (in react-dashboard/)")
    logger.info("  main.py pipeline: still runs independently via tshark pipe")
    logger.info("-" * 60)

    # ── Wait for all tasks (run until interrupted) ────────────────────────────
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logger.info("Shutdown signal received — cancelling tasks...")
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("All tasks cancelled. Goodbye.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user.")
