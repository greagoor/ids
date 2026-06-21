"""
rag/chatbot.py — Grounded Gemini chatbot for SOC analyst queries

Takes RAG-retrieved context + user query, builds a grounded prompt,
and returns a Gemini-generated answer. Only uses data from Supabase
(via ChromaDB) — will explicitly say "I don't have data on that" rather
than hallucinating specific IPs/attack details.
"""

import logging
import os
from typing import Optional

import google.genai as genai
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

GEMINI_MODEL = "gemini-2.5-flash"
_api_key = os.getenv("GEMINI_API_KEY", "")
_client  = genai.Client(api_key=_api_key) if _api_key else None


def _build_chat_prompt(user_query: str, context: str, analyst_role: str) -> str:
    role_note = (
        "You are assisting a junior SOC analyst. IP addresses in the context may be redacted ([REDACTED-IP]). "
        "Do not infer or guess actual IP addresses."
        if analyst_role == "junior"
        else
        "You are assisting a senior SOC analyst. Full context including IPs is available."
    )
    return f"""You are a cybersecurity AI assistant for a Security Operations Center (SOC).
{role_note}

IMPORTANT RULES:
1. Only use information from the CONTEXT BELOW to answer questions about security events, alerts, and IPs. Do not invent attack details or incidents.
2. If asked about a security event that is not in the context, say: "I don't have enough data in the knowledge base to answer that reliably."
3. If the user asks a conversational question (e.g., "how are you", "who are you"), respond naturally without citing the knowledge base.
4. Be concise and precise — this is a live security environment.
5. Always cite which data source (collection) the information came from, when discussing context.

CONTEXT FROM KNOWLEDGE BASE:
{context}

ANALYST QUERY:
{user_query}

ANSWER:"""


async def answer_query(
    user_query: str,
    analyst_role: str = "junior",
) -> dict:
    """
    Full RAG + Gemini answer pipeline.

    Returns:
        {
            "answer":   str,
            "sources":  list[str],   # collection names used
            "grounded": bool,        # False if no context found
        }
    """
    from rag.rag_engine import query_rag, format_context_for_prompt

    try:
        results = query_rag(user_query, analyst_role=analyst_role)
    except Exception as e:
        logger.error("[chatbot] RAG query failed: %s", e)
        results = []

    if not results:
        return {
            "answer":   "The knowledge base is empty or the query returned no relevant documents. Please ensure the knowledge ingest has run.",
            "sources":  [],
            "grounded": False,
        }

    context = format_context_for_prompt(results)
    sources = list(set(r["collection"] for r in results))

    if not _api_key:
        return {
            "answer":   f"**[Demo Mode: Gemini API Key Not Configured]**\n\nI searched the knowledge base and found the following relevant context:\n\n```text\n{context}\n```\n\n*In a live environment with a Gemini API key, I would synthesize this into a structured, analytical response based on your query.*",
            "sources":  sources,
            "grounded": True,
        }

    try:
        prompt = _build_chat_prompt(user_query, context, analyst_role)
        import asyncio
        loop   = asyncio.get_event_loop()
        resp   = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: _client.models.generate_content(
                    model    = GEMINI_MODEL,
                    contents = prompt,
                )
            ),
            timeout=30
        )
        answer = resp.text.strip()
    except Exception as e:
        logger.error("[chatbot] Gemini call failed: %s", e)
        answer = (
            f"Gemini unavailable ({e}). "
            f"Raw context:\n\n{context[:800]}"
        )

    return {
        "answer":   answer,
        "sources":  sources,
        "grounded": True,
    }
