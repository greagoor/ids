"""
agents/learning_agent.py — Drift detection + feedback-driven model monitoring

Background loop (APScheduler, every 5 minutes):
  1. Polls feedback table for new rows since last run
  2. Feeds a river.drift.ADWIN() detector with correct/incorrect signals
  3. Logs drift detection to model_metrics + console
  4. Does NOT automatically retrain (out of scope for 5-day timeline —
     see retrain_now() for manual trigger with before/after metrics)

RESEARCH-LAYER LIMITATION (documented):
  Full automated retrain pipeline is intentionally out of scope for this
  project iteration. The drift detection + metric logging infrastructure
  is in place so a future pipeline (e.g. a GitHub Actions workflow or
  a scheduled script) can call retrain_now() when drift is flagged.
"""

import asyncio
import logging
import os
import pickle
from datetime import datetime, timezone, timedelta
from typing import Optional

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

AGENT_NAME      = "learning_agent"
CHECK_INTERVAL  = 300   # seconds (5 minutes)
DRIFT_THRESHOLD = 5     # accumulated feedback count before forcing a check

# River ADWIN drift detector
try:
    from river.drift import ADWIN
    _adwin = ADWIN()
    _river_available = True
except ImportError:
    logger.warning("[learning_agent] `river` package not installed — drift detection disabled.")
    _river_available = False
    _adwin = None

_last_feedback_check: Optional[datetime] = None
_feedback_count_since_last_check = 0


# ── Feedback processing ───────────────────────────────────────────────────────

def _process_feedback_row(row: dict, original_verdict: Optional[str]) -> Optional[int]:
    """
    Convert a feedback row to a correct/incorrect signal (1/0) for ADWIN.
    
    Logic: if analyst says TP and model said attack → correct (1)
           if analyst says FP and model said attack → incorrect (0)
           UNSURE rows are skipped (return None)
    """
    analyst_verdict = (row.get("verdict") or "").upper()
    if analyst_verdict == "UNSURE":
        return None
    if analyst_verdict == "TP":
        return 1   # Model was right
    if analyst_verdict == "FP":
        return 0   # Model was wrong
    return None


async def _poll_feedback() -> None:
    global _last_feedback_check, _feedback_count_since_last_check, _adwin

    from cloud_db import _db, write_model_metrics, write_audit_log

    try:
        query = _db().table("feedback").select("*").order("timestamp", desc=False)
        if _last_feedback_check:
            query = query.gt("timestamp", _last_feedback_check.isoformat())
        res = query.execute()
        rows = res.data or []
    except Exception as e:
        logger.error("[learning_agent] feedback poll failed: %s", e)
        return

    if not rows:
        logger.debug("[learning_agent] No new feedback rows.")
        return

    logger.info("[learning_agent] Processing %d new feedback rows.", len(rows))
    _feedback_count_since_last_check += len(rows)

    drift_signals = []
    for row in rows:
        signal = _process_feedback_row(row, original_verdict=None)
        if signal is None:
            continue
        drift_signals.append(signal)

        if _river_available and _adwin is not None:
            _adwin.update(signal)

    # Check for drift
    drift_detected = False
    if _river_available and _adwin is not None and _adwin.drift_detected:
        drift_detected = True
        logger.warning(
            "[learning_agent] ⚠ ADWIN DRIFT DETECTED after %d feedback samples. "
            "Model performance may have degraded. Manual retraining recommended.",
            _feedback_count_since_last_check,
        )

    force_check = _feedback_count_since_last_check >= DRIFT_THRESHOLD
    if drift_detected or force_check:
        # Log metrics row
        correct   = sum(drift_signals)
        total     = max(len(drift_signals), 1)
        accuracy  = correct / total

        try:
            write_model_metrics({
                "accuracy":        accuracy,
                "precision_score": accuracy,   # simplified — full metrics need label data
                "recall_score":    accuracy,
                "f1_score":        accuracy,
                "drift_detected":  drift_detected,
            })
        except Exception as e:
            logger.error("[learning_agent] write_model_metrics failed: %s", e)

        try:
            write_audit_log(
                agent     = AGENT_NAME,
                action    = "DRIFT_DETECTED" if drift_detected else "FEEDBACK_THRESHOLD_REACHED",
                reasoning = (
                    f"ADWIN drift: {drift_detected}. "
                    f"Feedback since last check: {_feedback_count_since_last_check}. "
                    f"Estimated accuracy from feedback: {accuracy:.2%}. "
                    f"Retraining recommended — call retrain_now() manually."
                ),
                metadata  = {
                    "drift_detected": drift_detected,
                    "feedback_count": _feedback_count_since_last_check,
                    "accuracy_estimate": accuracy,
                },
            )
        except Exception as e:
            logger.error("[learning_agent] write_audit_log failed: %s", e)

        if drift_detected:
            _feedback_count_since_last_check = 0
            if _adwin:
                _adwin = ADWIN() if _river_available else None   # reset detector

    _last_feedback_check = datetime.now(timezone.utc)


# ── Manual retrain trigger (call from script — see RESEARCH-LAYER LIMITATION) ─

def retrain_now() -> dict:
    """
    Manual retrain trigger for the suspicion model.

    RESEARCH-LAYER LIMITATION: This function scaffolds the retrain flow but
    does NOT implement a full automated retraining pipeline (out of scope for
    5-day build timeline). It:
      1. Loads current model metrics (pre-retrain)
      2. Logs a model_metrics row with drift_detected=True as the trigger event
      3. Prints instructions for the developer to run the actual training script
      4. Logs before/after metrics once complete

    Future work: wire this into a GitHub Actions workflow or APScheduler job
    that calls ml/train_suspicion_model.py and reloads the model hot.
    """
    logger.warning(
        "[learning_agent] retrain_now() called — MANUAL RETRAIN REQUIRED.\n"
        "Run: python ml/train_suspicion_model.py\n"
        "Then restart the agent system to load the new model.\n"
        "This is the documented research-layer limitation of the 5-day build."
    )
    try:
        from cloud_db import write_model_metrics
        write_model_metrics({
            "accuracy":        0.0,
            "precision_score": 0.0,
            "recall_score":    0.0,
            "f1_score":        0.0,
            "drift_detected":  True,
        })
    except Exception as e:
        logger.error("retrain_now metrics write failed: %s", e)

    return {
        "status":  "RETRAIN_REQUIRED",
        "message": "Manual retrain triggered. Run: python ml/train_suspicion_model.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Main loop ─────────────────────────────────────────────────────────────────

async def run_forever() -> None:
    from cloud_db import update_agent_status
    update_agent_status(AGENT_NAME, "IDLE")
    logger.info("[learning_agent] started, checking feedback every %ds.", CHECK_INTERVAL)

    while True:
        try:
            update_agent_status(AGENT_NAME, "BUSY")
            await _poll_feedback()
            update_agent_status(AGENT_NAME, "IDLE")
        except Exception as e:
            logger.error("[learning_agent] loop error: %s", e)
            try:
                from cloud_db import update_agent_status
                update_agent_status(AGENT_NAME, "ERROR")
            except Exception:
                pass

        await asyncio.sleep(CHECK_INTERVAL)
