"""tools/chroma_debug.py — inspect ChromaDB IP metadata for 10.0.0.41"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv; load_dotenv(override=True)
import chromadb

c = chromadb.PersistentClient(path="chroma_db")

TARGET_IP = "10.0.0.41"
WHERE = {"ip": {"$eq": TARGET_IP}}

for col_name in ["alerts_summary", "audit_log", "incident_summaries"]:
    col = c.get_or_create_collection(col_name)
    print(f"\n{'='*60}")
    print(f"  {col_name}  ({col.count()} total docs)")
    try:
        r = col.get(where=WHERE)
        ids = r.get("ids", [])
        docs = r.get("documents", [])
        metas = r.get("metadatas", [])
        print(f"  Docs with ip={TARGET_IP}: {len(ids)}")
        for doc_id, doc, meta in zip(ids, docs, metas):
            print(f"    id={doc_id}")
            print(f"    meta={meta}")
            print(f"    doc: {doc[:120]}")
    except Exception as e:
        print(f"  WHERE filter FAILED: {e}")

    # Sample 3 random docs to see what ip values look like
    sample = col.get(limit=3)
    print(f"  Sample metadata (first 3 docs):")
    for meta in (sample.get("metadatas") or []):
        print(f"    {meta}")
