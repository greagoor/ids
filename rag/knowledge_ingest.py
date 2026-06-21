"""
rag/knowledge_ingest.py — ChromaDB knowledge base builder

Periodically (and on-demand via FastAPI endpoint) pulls rows from:
  - alerts, incidents, audit_log, honeypot_logs (from Supabase)
  - MITRE ATT&CK technique descriptions (from enterprise-attack.json)

Embeds with sentence-transformers (all-MiniLM-L6-v2) and upserts into
local ChromaDB collections.

Collections:
  alerts_summary, incident_summaries, audit_log, mitre_data,
  honeypot_logs, blocklist_data
"""

import asyncio
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

CHROMA_PATH      = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "chroma_db")
EMBEDDING_MODEL  = "all-MiniLM-L6-v2"
INGEST_INTERVAL  = 300   # seconds between auto-refresh

_chroma_client   = None
_embedder        = None
_initialized     = False


def _get_chroma():
    global _chroma_client
    if _chroma_client is None:
        import chromadb
        _chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
    return _chroma_client


def _get_embedder():
    global _embedder
    if _embedder is None:
        print(
            "\n[RAG] First run — downloading sentence-transformers model "
            f"'{EMBEDDING_MODEL}' (~90MB). This may take a minute...\n"
        )
        from sentence_transformers import SentenceTransformer
        _embedder = SentenceTransformer(EMBEDDING_MODEL)
        print("[RAG] Embedding model loaded.\n")
    return _embedder


def _embed_texts(texts: list[str]) -> list[list[float]]:
    return _get_embedder().encode(texts, show_progress_bar=False).tolist()


def _upsert_to_collection(collection_name: str, docs: list[str], ids: list[str], metadatas: list[dict]) -> int:
    """Upsert documents into a ChromaDB collection. Returns count upserted."""
    if not docs:
        return 0
    try:
        client     = _get_chroma()
        collection = client.get_or_create_collection(collection_name)
        embeddings = _embed_texts(docs)
        collection.upsert(
            documents  = docs,
            embeddings = embeddings,
            ids        = ids,
            metadatas  = metadatas,
        )
        return len(docs)
    except Exception as e:
        logger.error("[knowledge_ingest] upsert to %s failed: %s", collection_name, e)
        return 0


# ── Per-table ingestion functions ─────────────────────────────────────────────

def _ingest_alerts(since: Optional[str] = None) -> int:
    from cloud_db import _db
    try:
        query = _db().table("alerts").select("*").order("timestamp", desc=True).limit(500)
        if since:
            query = query.gt("timestamp", since)
        res  = query.execute()
        rows = res.data or []
    except Exception as e:
        logger.error("[knowledge_ingest] alerts fetch failed: %s", e)
        return 0

    docs, ids, metas = [], [], []
    for row in rows:
        doc = (
            f"Alert: {row.get('attack_type','?')} from {row.get('ip','?')}. "
            f"URL: {str(row.get('url',''))[:100]}. "
            f"Severity: {row.get('severity','?')}. "
            f"Verdict: {row.get('verdict','?')}. "
            f"ML score: {row.get('suspicion_score','?')}. "
            f"Rule: {row.get('rule_match','none')}. "
            f"Timestamp: {row.get('timestamp','?')}."
        )
        docs.append(doc)
        ids.append(f"alert_{row['id']}")
        metas.append({
            "ip":          str(row.get("ip", "")),
            "attack_type": str(row.get("attack_type", "")),
            "severity":    str(row.get("severity", "")),
            "timestamp":   str(row.get("timestamp", "")),
        })
    return _upsert_to_collection("alerts_summary", docs, ids, metas)


def _ingest_incidents(since: Optional[str] = None) -> int:
    from cloud_db import _db
    try:
        query = _db().table("incidents").select("*").order("last_seen", desc=True).limit(200)
        res   = query.execute()
        rows  = res.data or []
    except Exception as e:
        logger.error("[knowledge_ingest] incidents fetch failed: %s", e)
        return 0

    docs, ids, metas = [], [], []
    for row in rows:
        mitre_tags = row.get("mitre_tags") or []
        tag_str = ", ".join(
            t.get("technique_id", "") if isinstance(t, dict) else str(t)
            for t in mitre_tags
        )
        doc = (
            f"Incident: IP {row.get('ip','?')} performed {row.get('attack_type','?')} "
            f"{row.get('count','?')} times. Status: {row.get('status','?')}. "
            f"Severity: {row.get('severity','?')}. MITRE: {tag_str or 'none'}. "
            f"Kill chain: {row.get('kill_chain_phase','?')}."
        )
        docs.append(doc)
        ids.append(f"incident_{row['id']}")
        metas.append({
            "ip":          str(row.get("ip", "")),
            "attack_type": str(row.get("attack_type", "")),
            "status":      str(row.get("status", "")),
        })
    return _upsert_to_collection("incident_summaries", docs, ids, metas)


def _ingest_audit_log(since: Optional[str] = None) -> int:
    from cloud_db import _db
    try:
        query = _db().table("audit_log").select("*").order("timestamp", desc=True).limit(300)
        if since:
            query = query.gt("timestamp", since)
        res  = query.execute()
        rows = res.data or []
    except Exception as e:
        logger.error("[knowledge_ingest] audit_log fetch failed: %s", e)
        return 0

    # Extract alert_ids and fetch their IPs to tag audit rows with the correct IP
    alert_ids = list({r["alert_id"] for r in rows if r.get("alert_id")})
    alert_ips = {}
    if alert_ids:
        try:
            res_alerts = _db().table("alerts").select("alert_uuid, ip").in_("alert_uuid", alert_ids).execute()
            for a in (res_alerts.data or []):
                alert_ips[a["alert_uuid"]] = str(a.get("ip", ""))
        except Exception as e:
            logger.error("[knowledge_ingest] alerts ip fetch failed: %s", e)

    docs, ids, metas = [], [], []
    for row in rows:
        doc = (
            f"Agent action: {row.get('agent','?')} performed {row.get('action','?')}. "
            f"Reasoning: {str(row.get('reasoning',''))[:200]}. "
            f"Timestamp: {row.get('timestamp','?')}."
        )
        docs.append(doc)
        ids.append(f"audit_{row['id']}")
        # Extract ip from the associated alert or the row's metadata JSON
        alert_id = row.get("alert_id")
        ip_val = alert_ips.get(alert_id, "")
        if not ip_val:
            row_meta = row.get("metadata") or {}
            ip_val = str(row_meta.get("ip", "")) if isinstance(row_meta, dict) else ""
        metas.append({
            "agent":  str(row.get("agent", "")),
            "action": str(row.get("action", "")),
            "ip":     ip_val,
        })
    return _upsert_to_collection("audit_log", docs, ids, metas)


def _ingest_mitre() -> int:
    """Ingest MITRE technique descriptions into mitre_data collection."""
    from intel.mitre_mapper import _MITRE_DB, _ATTACK_TO_TECHNIQUE_IDS

    docs, ids, metas = [], [], []
    for tech_id, info in _MITRE_DB.items():
        doc = (
            f"MITRE {tech_id}: {info.get('name','?')}. "
            f"{info.get('description','')[:300]}"
        )
        docs.append(doc)
        ids.append(f"mitre_{tech_id.replace('.', '_')}")
        metas.append({"technique_id": tech_id, "name": info.get("name", "")})
    return _upsert_to_collection("mitre_data", docs, ids, metas)


def _ingest_honeypot_logs(since: Optional[str] = None) -> int:
    from cloud_db import _db
    try:
        query = _db().table("honeypot_logs").select("*").order("timestamp", desc=True).limit(200)
        if since:
            query = query.gt("timestamp", since)
        res  = query.execute()
        rows = res.data or []
    except Exception as e:
        logger.error("[knowledge_ingest] honeypot_logs fetch failed: %s", e)
        return 0

    docs, ids, metas = [], [], []
    for row in rows:
        doc = (
            f"Honeypot hit: IP {row.get('ip','?')} accessed {row.get('endpoint','?')}. "
            f"Payload: {str(row.get('payload',''))[:150]}. "
            f"Timestamp: {row.get('timestamp','?')}."
        )
        docs.append(doc)
        ids.append(f"honeypot_{row['id']}")
        metas.append({
            "ip":       str(row.get("ip", "")),
            "endpoint": str(row.get("endpoint", "")),
        })
    return _upsert_to_collection("honeypot_logs", docs, ids, metas)


# ── Full ingest (on-demand or periodic) ──────────────────────────────────────

def run_full_ingest(since: Optional[str] = None) -> dict:
    """
    Run all ingest functions. Returns counts per collection.
    Call this on-demand from FastAPI or let the background loop call it.
    """
    logger.info("[knowledge_ingest] Starting full knowledge base ingest...")
    results = {
        "alerts_summary":    _ingest_alerts(since),
        "incident_summaries": _ingest_incidents(since),
        "audit_log":         _ingest_audit_log(since),
        "mitre_data":        _ingest_mitre(),
        "honeypot_logs":     _ingest_honeypot_logs(since),
    }
    total = sum(results.values())
    logger.info("[knowledge_ingest] Ingest complete. Total docs upserted: %d. %s", total, results)
    return results


async def run_forever() -> None:
    """Background periodic ingest loop."""
    logger.info("[knowledge_ingest] Starting periodic ingest (every %ds).", INGEST_INTERVAL)
    last_run = None

    while True:
        await asyncio.sleep(INGEST_INTERVAL)
        try:
            since = last_run
            results = run_full_ingest(since=since)
            last_run = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            logger.error("[knowledge_ingest] periodic ingest failed: %s", e)
