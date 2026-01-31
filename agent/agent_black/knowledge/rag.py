#!/usr/bin/env python3
"""
Agent BLACK RAG (Retrieval Augmented Generation)

Query the vector database to retrieve relevant knowledge
for answering questions and solving problems.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional

KNOWLEDGE_DIR = Path(__file__).parent
DB_DIR = KNOWLEDGE_DIR / "vector_db"
EMBED_MODEL = "nomic-embed-text"
OLLAMA_URL = "http://localhost:11434"
TOP_K = 5

_vectordb = None
_embeddings = None


def _get_vectordb():
    global _vectordb, _embeddings
    
    if _vectordb is not None:
        return _vectordb
    
    if not DB_DIR.exists():
        return None
    
    try:
        from langchain_community.embeddings import OllamaEmbeddings
        from langchain_community.vectorstores import Chroma
        
        _embeddings = OllamaEmbeddings(
            model=EMBED_MODEL,
            base_url=OLLAMA_URL
        )
        
        _vectordb = Chroma(
            persist_directory=str(DB_DIR),
            embedding_function=_embeddings
        )
        
        return _vectordb
    except ImportError:
        return None
    except Exception:
        return None


def is_available() -> bool:
    return _get_vectordb() is not None


def get_chunk_count() -> int:
    db = _get_vectordb()
    if db is None:
        return 0
    try:
        return db._collection.count()
    except:
        return 0


def query(question: str, top_k: int = TOP_K) -> List[Dict[str, Any]]:
    db = _get_vectordb()
    if db is None:
        return []
    
    try:
        results = db.similarity_search(question, k=top_k)
        
        output = []
        for doc in results:
            output.append({
                "content": doc.page_content,
                "source": doc.metadata.get("source", "unknown"),
                "chunk": doc.metadata.get("chunk", 0),
            })
        
        return output
    except Exception as e:
        return []


def query_with_context(question: str, top_k: int = TOP_K) -> Dict[str, Any]:
    results = query(question, top_k)
    
    if not results:
        return {
            "context": "",
            "sources": [],
            "chunk_count": 0,
        }
    
    context_parts = []
    sources = set()
    
    for r in results:
        context_parts.append(r["content"])
        sources.add(r["source"])
    
    return {
        "context": "\n\n---\n\n".join(context_parts),
        "sources": list(sources),
        "chunk_count": len(results),
    }


def build_rag_prompt(question: str, system_prompt: str = "", top_k: int = TOP_K) -> str:
    result = query_with_context(question, top_k)
    
    if not result["context"]:
        return f"{system_prompt}\n\nQuestion: {question}" if system_prompt else question
    
    prompt = ""
    if system_prompt:
        prompt += f"{system_prompt}\n\n"
    
    prompt += f"""CONTEXT FROM KNOWLEDGE BASE:
{result['context']}

QUESTION: {question}

Use the context above to help answer the question. If the context doesn't contain relevant information, say so but still try to help based on your training.

ANSWER:"""
    
    return prompt


def search_for_technique(technique: str) -> List[Dict[str, Any]]:
    queries = [
        f"how to {technique}",
        f"{technique} tutorial",
        f"{technique} example",
        f"{technique} attack",
    ]
    
    all_results = []
    seen_chunks = set()
    
    for q in queries:
        results = query(q, top_k=3)
        for r in results:
            chunk_key = (r["source"], r["chunk"])
            if chunk_key not in seen_chunks:
                seen_chunks.add(chunk_key)
                all_results.append(r)
    
    return all_results[:10]


def get_sources() -> List[str]:
    db = _get_vectordb()
    if db is None:
        return []
    
    try:
        all_docs = db._collection.get()
        sources = set()
        for meta in all_docs.get("metadatas", []):
            if "source" in meta:
                sources.add(meta["source"])
        return sorted(list(sources))
    except:
        return []


def search_in_source(source_name: str, query_text: str, top_k: int = 5) -> List[Dict[str, Any]]:
    db = _get_vectordb()
    if db is None:
        return []
    
    try:
        results = db.similarity_search(
            query_text,
            k=top_k * 2,
            filter={"source": source_name}
        )
        
        output = []
        for doc in results[:top_k]:
            output.append({
                "content": doc.page_content,
                "source": doc.metadata.get("source", "unknown"),
                "chunk": doc.metadata.get("chunk", 0),
            })
        
        return output
    except:
        return []


if __name__ == "__main__":
    print("Agent BLACK RAG Module")
    print("=" * 40)
    print(f"Database: {DB_DIR}")
    print(f"Available: {is_available()}")
    print(f"Chunks: {get_chunk_count()}")
    
    sources = get_sources()
    if sources:
        print(f"\nSources ({len(sources)}):")
        for s in sources[:10]:
            print(f"  - {s}")
        if len(sources) > 10:
            print(f"  ... and {len(sources) - 10} more")
    
    if is_available():
        print("\nTest query: 'SQL injection bypass'")
        results = query("SQL injection bypass", top_k=3)
        for i, r in enumerate(results):
            print(f"\n[{i+1}] {r['source']}")
            print(f"    {r['content'][:200]}...")
