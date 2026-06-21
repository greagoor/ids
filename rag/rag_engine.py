"""
rag/rag_engine.py — Role-aware RAG retrieval engine

query_rag(user_query, analyst_role) -> list[dict]

Two-role access control:
  junior: alerts_summary, mitre_data, incident_summaries
          (IPv4 addresses are redacted in returned context)
  senior: all collections including audit_log, blocklist_data, honeypot_logs
          (full context, no redaction)
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

ROLE_ALLOWED_COLLECTIONS = {
    "junior": ["alerts_summary", "mitre_data", "incident_summaries"],
    "senior": ["alerts_summary", "mitre_data", "incident_summaries",
               "audit_log", "blocklist_data", "honeypot_logs"],
}

# Collections that store an "ip" field in their ChromaDB metadata
_IP_FILTERABLE_COLLECTIONS = {"alerts_summary", "incident_summaries", "honeypot_logs", "audit_log"}

_IPV4_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
TOP_K = 5   # documents per collection


def _extract_ip(query: str) -> Optional[str]:
    """Return the first IPv4 address found in the query string, or None."""
    m = _IPV4_PATTERN.search(query)
    return m.group(0) if m else None


def _redact_ips(text: str) -> str:
    """Replace all IPv4 addresses with [REDACTED-IP]."""
    return _IPV4_PATTERN.sub("[REDACTED-IP]", text)


def _get_chroma():
    from rag.knowledge_ingest import _get_chroma
    return _get_chroma()


def _get_embedder():
    from rag.knowledge_ingest import _get_embedder
    return _get_embedder()


def query_rag(
    user_query: str,
    analyst_role: str = "junior",
    top_k: int = TOP_K,
) -> list[dict]:
    """
    Retrieve relevant context from ChromaDB for the given query.

    Returns list of dicts:
        [{"collection": str, "document": str, "metadata": dict, "distance": float}]

    For junior role: IPv4 addresses in documents are redacted before return.
    """
    role = analyst_role.lower()
    allowed = ROLE_ALLOWED_COLLECTIONS.get(role, ROLE_ALLOWED_COLLECTIONS["junior"])
    redact  = (role == "junior")

    client  = _get_chroma()
    embedder = _get_embedder()

    query_embedding = embedder.encode([user_query], show_progress_bar=False)[0].tolist()

    # If the query mentions a specific IP, use it as a metadata pre-filter
    # in collections that index the IP field — prevents irrelevant IPs from
    # semantically swamping the target IP's docs.
    query_ip = _extract_ip(user_query)

    results = []
    for collection_name in allowed:
        try:
            collection = client.get_or_create_collection(collection_name)
            # Skip if empty
            if collection.count() == 0:
                continue

            # Build optional where-filter for IP-aware collections
            where = None
            if query_ip and collection_name in _IP_FILTERABLE_COLLECTIONS:
                # Check if the collection actually has any doc with this IP
                ip_check = collection.get(where={"ip": {"$eq": query_ip}}, limit=1)
                if ip_check and ip_check.get("ids"):
                    where = {"ip": {"$eq": query_ip}}
                else:
                    # If this collection tracks IPs but has no docs for this IP, skip it!
                    # Do not fall back to unfiltered semantic search, or it will return
                    # irrelevant IPs that outrank the target IP due to structural similarity.
                    continue

            query_kwargs = dict(
                query_embeddings = [query_embedding],
                n_results        = min(top_k, collection.count()),
                include          = ["documents", "metadatas", "distances"],
            )
            if where:
                # Count how many docs match the IP filter
                ip_count = len(collection.get(where=where).get("ids", []))
                query_kwargs["n_results"] = min(top_k, ip_count)
                query_kwargs["where"]     = where

            res = collection.query(**query_kwargs)
            docs      = res.get("documents", [[]])[0]
            metas     = res.get("metadatas", [[]])[0]
            distances = res.get("distances", [[]])[0]

            for doc, meta, dist in zip(docs, metas, distances):
                if redact:
                    doc  = _redact_ips(doc)
                    meta = {k: _redact_ips(str(v)) for k, v in meta.items()}

                results.append({
                    "collection": collection_name,
                    "document":   doc,
                    "metadata":   meta,
                    "distance":   round(float(dist), 4),
                })
        except Exception as e:
            logger.warning("[rag_engine] query on %s failed: %s", collection_name, e)

    # Sort by relevance (lower distance = more relevant)
    results.sort(key=lambda x: x["distance"])
    return results[:top_k * 2]   # cap total results


def format_context_for_prompt(results: list[dict]) -> str:
    """Format RAG results into a compact prompt context block."""
    if not results:
        return "No relevant context found in knowledge base."
    lines = []
    for i, r in enumerate(results, 1):
        lines.append(f"[{i}] ({r['collection']}) {r['document']}")
    return "\n".join(lines)
