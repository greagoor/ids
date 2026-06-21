"""
agents/detection_agent.py — Entry point of the agent pipeline

Callable from two contexts:
  (a) additively from main.py's per-request loop (enqueue_alert)
  (b) standalone from FastAPI honeypot/demo endpoints (run_detection)

Pipeline per request:
  1. Multi-layer decode via core/decoder_chain.py
  2. Blocklist fast-path (skip to CRITICAL if hit)
  3. Rule detectors (existing detectors/*)
  4. ML suspicion scorer (ml/suspicion_scorer.py)
  5. ML payload scorer (ml/payload_scorer.py) — only when warranted
  6. Session tracker update + read back behavioral flags
  7. Fusion logic → verdict (HIGH/MEDIUM/SUSPICIOUS/CRITICAL)
  8. Write to agent_queue (routes to pretriage or response agent)
  9. Write full alert row to alerts table
  10. Update agent_status heartbeat
"""

import asyncio
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ── Detector imports (frozen — do not modify) ─────────────────────────────────
from detectors import sqli, xss, cmdi, lfi, rfi, ssrf, path_traversal

DETECTORS = [
    ("SQL_INJECTION",    sqli.detect),
    ("COMMAND_INJECTION", cmdi.detect),
    ("XSS",              xss.detect),
    ("LFI",              lfi.detect),
    ("PATH_TRAVERSAL",   path_traversal.detect),
    ("RFI",              rfi.detect),
    ("SSRF",             ssrf.detect),
]

AGENT_NAME = "detection_agent"


# ── Fusion verdict logic ──────────────────────────────────────────────────────

def _determine_verdict(
    rule_match: Optional[str],
    ml_score: float,
    is_blocklisted: bool,
    session_flags: dict,
) -> tuple[str, str]:
    """
    Apply fusion rules and return (verdict, receiver).

    Fusion table:
      blocklisted                       → CRITICAL  → response_agent
      rule + ml_score > 0.7             → HIGH      → response_agent
      rule + ml_score ≤ 0.7             → MEDIUM    → pretriage_agent
      ml_score > 0.6 + no rule          → SUSPICIOUS→ pretriage_agent (investigation)
      rule + no ml_score                → check session → MEDIUM or LOW
    """
    if is_blocklisted:
        return "CRITICAL", "response_agent"

    has_rule = rule_match is not None

    if has_rule and ml_score > 0.7:
        return "HIGH", "response_agent"

    if has_rule and ml_score > 0:
        return "MEDIUM", "pretriage_agent"

    if not has_rule and ml_score > 0.6:
        return "SUSPICIOUS", "pretriage_agent"

    if has_rule and ml_score == 0:
        # No ML score — use session escalation as tiebreaker
        esc = session_flags.get("escalation_score", 0)
        if esc > 50 or session_flags.get("is_multi_vector"):
            return "HIGH", "response_agent"
        return "MEDIUM", "pretriage_agent"

    # Nothing triggered
    return "LOW", "pretriage_agent"


# ── Core detection pipeline ───────────────────────────────────────────────────

def run_detection(
    ip: str,
    method: str,
    url: str,
    response_code: str = "",
    raw_payload: str = "",
    outcome: str = "ATTEMPT",
    source: str = "tshark",
) -> dict:
    """
    Run the full detection pipeline for a single request.
    Returns the enriched alert dict. Safe to call from any thread.

    Args:
        ip:           Source IP
        method:       HTTP method
        url:          Full URI (decoded or raw)
        response_code: HTTP response code string
        raw_payload:  Raw query string / POST body if available
        outcome:      "ATTEMPT" or "LIKELY_SUCCESSFUL"
        source:       "tshark" | "honeypot" | "demo"
    """
    # ── 1. Decode ─────────────────────────────────────────────────────────────
    from core.decoder_chain import decode_payload
    decode_result   = decode_payload(url)
    decoded_url     = decode_result["decoded"]
    was_obfuscated  = decode_result["was_obfuscated"]

    # Decode payload separately (could be query string or POST body)
    payload_to_score = raw_payload or (decoded_url.split("?", 1)[1] if "?" in decoded_url else "")
    payload_decode   = decode_payload(payload_to_score) if payload_to_score else {"decoded": ""}
    decoded_payload  = payload_decode["decoded"]

    # ── 2. Blocklist fast-path ────────────────────────────────────────────────
    from intel.blocklist import is_blocklisted, record_ip_seen
    record_ip_seen(ip)
    blocklisted = is_blocklisted(ip)

    if blocklisted:
        logger.warning("BLOCKLISTED IP detected: %s — skipping to CRITICAL verdict.", ip)

    # ── 3. Rule detectors ─────────────────────────────────────────────────────
    rule_match: Optional[str]  = None
    rule_indicators: list[str] = []

    for attack_type, detector_fn in DETECTORS:
        try:
            detected, indicators = detector_fn(decoded_url)
            if detected:
                rule_match       = attack_type
                rule_indicators  = indicators
                break
        except Exception as e:
            logger.error("Detector %s failed: %s", attack_type, e)

    # ── 4. Suspicion scorer ───────────────────────────────────────────────────
    suspicion_result: dict = {}
    ml_score:        float = 0.0
    shap_features:   list  = []

    try:
        from ml.suspicion_scorer import score_url
        suspicion_result = score_url(decoded_url)
        ml_score         = suspicion_result.get("suspicion_score", 0.0)
        shap_features    = suspicion_result.get("top_features", [])
    except Exception as e:
        logger.error("suspicion_scorer failed: %s", e)

    # ── 5. Payload classifier (run when rule or ml suggests attack) ───────────
    payload_result:      dict          = {}
    payload_attack_type: Optional[str] = None

    should_classify = (
        rule_match is not None or ml_score > 0.4
    ) and decoded_payload

    if should_classify:
        if blocklisted:
            # Fast-path: run classification completely in the background so we don't delay the CRITICAL verdict
            def _async_classify(pl: str):
                try:
                    from ml.payload_scorer import classify_payload
                    from cloud_db import _db
                    res = classify_payload(pl)
                    pat = res.get("attack_type", "Unknown")
                    if pat != "Benign":
                        # We don't have alert_id here easily since it's generated below,
                        # but we can rely on the fact that payload_scorer isn't critical for blocklisted IPs.
                        pass
                except Exception as e:
                    logger.error("async payload_scorer failed: %s", e)
            import threading
            threading.Thread(target=_async_classify, args=(decoded_payload,), daemon=True).start()
        else:
            try:
                from ml.payload_scorer import classify_payload
                payload_result      = classify_payload(decoded_payload)
                pat                 = payload_result.get("attack_type", "Unknown")
                payload_attack_type = pat if pat != "Benign" else None
            except Exception as e:
                logger.error("payload_scorer failed: %s", e)

    # ── 6. Session tracker ────────────────────────────────────────────────────
    from core.session_tracker import record_request, get_session_flags
    record_request(
        ip            = ip,
        endpoint      = decoded_url.split("?")[0],
        response_code = response_code,
        attack_type   = rule_match or payload_attack_type,
        suspicion_score = ml_score,
    )
    session_flags = get_session_flags(ip)

    # ── 7. Fusion verdict ─────────────────────────────────────────────────────
    verdict, queue_receiver = _determine_verdict(
        rule_match     = rule_match,
        ml_score       = ml_score,
        is_blocklisted = blocklisted,
        session_flags  = session_flags,
    )

    # Determine final attack_type label
    final_attack_type = rule_match or payload_attack_type or (
        suspicion_result.get("verdict", "SUSPICIOUS") if ml_score > 0.5 else "UNKNOWN"
    )

    # ── 8. Build alert dict ───────────────────────────────────────────────────
    from intel.mitre_mapper import map_attack_to_technique
    from intel.kill_chain   import identify_kill_chain_phase

    mitre_tags     = map_attack_to_technique(final_attack_type) if final_attack_type != "UNKNOWN" else []
    kill_chain     = identify_kill_chain_phase(final_attack_type, decoded_payload, session_flags)

    from core.severity import severity_from_confidence
    from core.scoring  import calculate_confidence

    confidence, _ = calculate_confidence(
        attack_type   = final_attack_type,
        indicators    = rule_indicators,
        uri           = decoded_url,
        response_code = response_code,
    )

    severity = severity_from_confidence(confidence, outcome)
    if verdict == "CRITICAL":
        severity = "CRITICAL"
    elif verdict == "HIGH" and severity not in ("CRITICAL", "HIGH"):
        severity = "HIGH"

    alert_id = str(uuid.uuid4())
    alert = {
        "alert_uuid":          alert_id,
        "timestamp":           datetime.now(timezone.utc).isoformat(),
        "ip":                  ip,
        "src_ip":              ip,   # kept for backward compat with main.py
        "method":              method,
        "url":                 url,
        "uri":                 url,  # backward compat
        "attack_type":         final_attack_type,
        "outcome":             outcome,
        "confidence":          confidence,
        "severity":            severity,
        "verdict":             verdict,
        "rule_match":          rule_match,
        "ml_score":            ml_score,
        "suspicion_score":     ml_score,
        "shap_features":       shap_features,
        "payload":             decoded_payload[:1000] if decoded_payload else None,
        "payload_attack_type": payload_attack_type,
        "mitre_tags":          mitre_tags,
        "kill_chain_phase":    kill_chain,
        "was_obfuscated":      was_obfuscated,
        "session_flags":       session_flags,
        "source":              source,
    }

    # ── 9. Write alert to DB immediately ──────────────────────────────────────
    try:
        from cloud_db import save_alert, upsert_incident
        save_alert(alert)
        upsert_incident({**alert, "threat_score": ml_score * 100})
    except Exception as e:
        logger.error("Failed to persist alert to DB: %s", e)

    # ── 10. Write to agent_queue ───────────────────────────────────────────────
    try:
        from cloud_db import write_to_queue, update_agent_status, write_audit_log
        update_agent_status(AGENT_NAME, "BUSY", alert_id)

        priority = "HIGH" if verdict in ("CRITICAL", "HIGH") else "MEDIUM"
        write_to_queue(
            sender    = AGENT_NAME,
            receiver  = queue_receiver,
            payload   = {k: v for k, v in alert.items() if isinstance(v, (str, int, float, bool, list, dict, type(None)))},
            alert_id  = alert_id,
            priority  = priority,
        )

        write_audit_log(
            agent     = AGENT_NAME,
            action    = "ALERT_DETECTED",
            reasoning = (
                f"rule={rule_match}, ml_score={ml_score:.3f}, "
                f"verdict={verdict}, routed_to={queue_receiver}"
            ),
            metadata  = {
                "verdict": verdict, "rule_match": rule_match,
                "ml_score": ml_score, "was_obfuscated": was_obfuscated,
            },
            alert_id  = alert_id,
        )

        update_agent_status(AGENT_NAME, "IDLE")
    except Exception as e:
        logger.error("Failed to write to agent_queue: %s", e)

    logger.info(
        "[detection_agent] ip=%s attack=%s verdict=%s ml=%.3f rule=%s → %s",
        ip, final_attack_type, verdict, ml_score, rule_match, queue_receiver,
    )

    return alert


# ── Lightweight bridge for main.py (no duplicate detection) ───────────────────

def enqueue_from_main(alert: dict) -> None:
    """
    Called additively from main.py after its full detection pipeline.

    Design contract:
      - main.py already ran: decode_uri, rule detectors, old ML predict(),
        calculate_confidence, build_alert, persist() (writes alerts + incidents).
      - This function does ONLY the NEW work not present in main.py:
          1. Blocklist fast-path check
          2. suspicion_scorer  (new model, different from predict())
          3. payload_scorer
          4. session_tracker   (behavioral sliding window)
          5. MITRE + kill_chain tagging
          6. Fusion verdict
          7. agent_queue INSERT  (routes to pretriage or response agent)
          8. audit_log INSERT
      - Does NOT call save_alert() or upsert_incident() — persist() already did.
      - Runs in a daemon thread so main.py's stdin loop is never blocked.
    """
    def _run():
        try:
            _bridge_pipeline(alert)
        except Exception as e:
            logger.error("enqueue_from_main background thread failed: %s", e)

    threading.Thread(target=_run, daemon=True).start()


def _bridge_pipeline(pre_alert: dict) -> None:
    """
    Lightweight pipeline that accepts main.py's already-built alert dict
    and only adds the new-system enrichments + queue write.
    """
    import uuid
    from datetime import datetime, timezone

    ip            = pre_alert.get("src_ip") or pre_alert.get("ip", "")
    url           = pre_alert.get("uri") or pre_alert.get("url", "")
    method        = pre_alert.get("method", "GET")
    response_code = str(pre_alert.get("response_code", ""))
    outcome       = pre_alert.get("outcome", "ATTEMPT")
    # main.py's already-computed rule/ML result — use as rule_match
    rule_match    = pre_alert.get("attack_type")
    confidence    = pre_alert.get("confidence", 0)

    # ── 1. Blocklist check (new — main.py doesn't do this) ────────────────────
    try:
        from intel.blocklist import is_blocklisted, record_ip_seen
        record_ip_seen(ip)
        blocklisted = is_blocklisted(ip)
    except Exception as e:
        logger.error("blocklist check failed: %s", e)
        blocklisted = False

    # ── 2. Suspicion scorer (new model — different from main.py's predict()) ──
    ml_score     = 0.0
    shap_features = []
    try:
        from ml.suspicion_scorer import score_url
        result   = score_url(url)
        ml_score = result.get("suspicion_score", 0.0)
        shap_features = result.get("top_features", [])
    except Exception as e:
        logger.error("suspicion_scorer failed: %s", e)

    # ── 3. Payload scorer (only when warranted) ───────────────────────────────
    payload_attack_type = None
    decoded_payload     = url.split("?", 1)[1] if "?" in url else ""
    if decoded_payload and (rule_match or ml_score > 0.4):
        if blocklisted:
            # Skip synchronous payload scoring for blocklisted IPs to preserve the fast-path speed
            def _async_classify(pl: str):
                try:
                    from ml.payload_scorer import classify_payload
                    classify_payload(pl)
                except Exception:
                    pass
            import threading
            threading.Thread(target=_async_classify, args=(decoded_payload,), daemon=True).start()
        else:
            try:
                from ml.payload_scorer import classify_payload
                res = classify_payload(decoded_payload)
                pat = res.get("attack_type", "Unknown")
                payload_attack_type = pat if pat != "Benign" else None
            except Exception as e:
                logger.error("payload_scorer failed: %s", e)

    # ── 4. Session tracker (new behavioral tracking) ─────────────────────────
    try:
        from core.session_tracker import record_request, get_session_flags
        record_request(
            ip              = ip,
            endpoint        = url.split("?")[0],
            response_code   = response_code,
            attack_type     = rule_match,
            suspicion_score = ml_score,
        )
        session_flags = get_session_flags(ip)
    except Exception as e:
        logger.error("session_tracker failed: %s", e)
        session_flags = {}

    # ── 5. Fusion verdict ─────────────────────────────────────────────────────
    verdict, queue_receiver = _determine_verdict(
        rule_match     = rule_match,
        ml_score       = ml_score,
        is_blocklisted = blocklisted,
        session_flags  = session_flags,
    )

    # ── 6. MITRE + kill-chain (new intel) ────────────────────────────────────
    try:
        from intel.mitre_mapper import map_attack_to_technique
        from intel.kill_chain   import identify_kill_chain_phase
        mitre_tags  = map_attack_to_technique(rule_match) if rule_match else []
        kill_chain  = identify_kill_chain_phase(rule_match or "", decoded_payload, session_flags)
    except Exception as e:
        logger.error("intel tagging failed: %s", e)
        mitre_tags, kill_chain = [], None

    # Reuse the alert_uuid from pre_alert for stable end-to-end tracing.
    # Only generate a fresh ID if none was provided (e.g. standalone API calls).
    alert_id = (
        pre_alert.get("alert_uuid")
        or pre_alert.get("alert_id")
        or str(uuid.uuid4())
    )
    enriched = {
        **pre_alert,                        # everything main.py already built
        "alert_uuid":       alert_id,
        "timestamp":        pre_alert.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "ip":               ip,
        "verdict":          verdict,
        "ml_score":         ml_score,
        "suspicion_score":  ml_score,
        "shap_features":    shap_features,
        "payload_attack_type": payload_attack_type,
        "mitre_tags":       mitre_tags,
        "kill_chain_phase": kill_chain,
        "session_flags":    session_flags,
        "source":           source,
        # NOTE: save_alert / upsert_incident intentionally NOT called here.
        # main.py's persist() already wrote to alerts + incidents.
    }

    # ── 8. Write to agent_queue + audit_log ──────────────────────────────────
    try:
        from cloud_db import write_to_queue, update_agent_status, write_audit_log
        update_agent_status(AGENT_NAME, "BUSY", alert_id)

        if source == "honeypot":
            queue_receiver = "honeypot_agent"

        priority = "HIGH" if verdict in ("CRITICAL", "HIGH") else "MEDIUM"
        write_to_queue(
            sender   = AGENT_NAME,
            receiver = queue_receiver,
            payload  = {k: v for k, v in enriched.items()
                        if isinstance(v, (str, int, float, bool, list, dict, type(None)))},
            alert_id = alert_id,
            priority = priority,
        )
        write_audit_log(
            agent     = AGENT_NAME,
            action    = "ALERT_DETECTED",
            reasoning = (
                f"[bridge] rule={rule_match} confidence={confidence} "
                f"ml_score={ml_score:.3f} verdict={verdict} → {queue_receiver}"
            ),
            metadata  = {
                "verdict": verdict, "rule_match": rule_match,
                "ml_score": ml_score, "source": "tshark",
                "blocklisted": blocklisted,
            },
            alert_id = alert_id,
        )
        update_agent_status(AGENT_NAME, "IDLE")
    except Exception as e:
        logger.error("agent_queue write failed: %s", e)

    logger.info(
        "[detection_agent/bridge] ip=%s attack=%s verdict=%s ml=%.3f → %s",
        ip, rule_match, verdict, ml_score, queue_receiver,
    )


# ── Backward-compat alias (kept for any external references) ───────────────────
enqueue_alert = enqueue_from_main
