# Agent BLACK Knowledge Base Guide

This guide covers setting up Agent BLACK's knowledge base - the AI "brain" that allows it to answer questions using your security books and documentation.

## How It Works

Agent BLACK uses RAG (Retrieval Augmented Generation):

1. **Ingestion**: PDFs/documents are chunked and converted to embeddings
2. **Storage**: Embeddings stored in a local ChromaDB vector database
3. **Query**: When you ask a question, relevant chunks are retrieved
4. **Response**: The LLM answers using the retrieved context

This means Agent BLACK can answer questions based on YOUR specific knowledge base.

## Requirements

```bash
pip install langchain langchain-community chromadb pymupdf ollama rich
```

You also need Ollama running with the embedding model:
```bash
ollama pull nomic-embed-text
ollama serve
```

## Adding Documents

### Supported Formats

- PDF files (`.pdf`)
- Text files (`.txt`)
- Markdown files (`.md`)

### Directory Structure

Place documents in `agent/agent_black/knowledge/pdfs/`:

```
agent/agent_black/knowledge/pdfs/
├── PenTesting/
│   ├── OSCP_Guide.pdf
│   ├── Web_Application_Hackers_Handbook.pdf
│   ├── Metasploit.pdf
│   └── Penetration_Testing.pdf
├── WebSec/
│   ├── Real_World_Bug_Hunting.pdf
│   └── Browser_Hackers_Handbook.pdf
├── NetworkSec/
│   ├── Nmap_Cookbook.pdf
│   └── Attacking_Network_Protocols.pdf
├── Crypto/
│   ├── Hash_Crack.pdf
│   └── Implementing_Cryptography_Python.pdf
├── ReverseEng/
│   ├── Ghidra_Book.pdf
│   └── Malware_Data_Science.pdf
└── Programming/
    ├── Black_Hat_Python.pdf
    └── Violent_Python.pdf
```

Subfolders are automatically scanned recursively.

## Running Ingestion

### Basic Ingestion

```bash
cd agent/agent_black/knowledge
python ingest.py
```

### Force Re-ingestion

If you've added new documents or want to rebuild:
```bash
python ingest.py --force
```

### Custom PDF Directory

```bash
python ingest.py --pdf-dir /path/to/your/pdfs
```

### Custom Ollama URL

```bash
python ingest.py --ollama-url http://192.168.1.100:11434
```

## Checking the Database

```bash
cd agent/agent_black/knowledge
python rag.py
```

Output:
```
Agent BLACK RAG Module
========================================
Database: /path/to/vector_db
Available: True
Chunks: 15432

Sources (10):
  - OSCP_Guide.pdf
  - Web_Application_Hackers_Handbook.pdf
  - Metasploit.pdf
  ...

Test query: 'SQL injection bypass'

[1] Web_Application_Hackers_Handbook.pdf
    SQL injection attacks can bypass authentication by injecting...
```

## Using in Agent BLACK

Once ingested, Agent BLACK automatically uses the knowledge base:

```
[YOU] > how do I bypass a WAF for SQL injection?

[BLACK] Based on the Web Application Hacker's Handbook, common WAF bypass 
techniques for SQL injection include:
1. Case manipulation: sElEcT instead of SELECT
2. Comment injection: SEL/**/ECT
3. URL encoding: %53%45%4C%45%43%54
4. Unicode encoding
...
[Sources: Web_Application_Hackers_Handbook.pdf]
```

## Programmatic Access

```python
from agent_black.knowledge import rag

# Check if available
print(rag.is_available())  # True
print(rag.get_chunk_count())  # 15432

# Query
results = rag.query("SQL injection bypass", top_k=5)
for r in results:
    print(f"[{r['source']}] {r['content'][:200]}...")

# Get context for LLM
context = rag.query_with_context("SSRF payloads")
print(context["context"])
print(context["sources"])

# Search for techniques
techniques = rag.search_for_technique("buffer overflow")

# List all sources
sources = rag.get_sources()
print(sources)

# Search in specific book
results = rag.search_in_source("Metasploit.pdf", "reverse shell")
```

## Recommended Books

### Essential (Start Here)
- **Web Application Hacker's Handbook** - Web security bible
- **OSCP Guide / PWK Materials** - Penetration testing methodology
- **Nmap Cookbook** - Network scanning reference

### Exploitation
- **Metasploit: The Penetration Tester's Guide**
- **Black Hat Python** - Python for hackers
- **Violent Python** - Offensive Python
- **Hacking: The Art of Exploitation**
- **Shellcoder's Handbook**

### Web Security
- **Real World Bug Hunting** - Bug bounty guide
- **Browser Hacker's Handbook** - Client-side attacks
- **Burp Suite Cookbook**

### Network Security
- **Attacking Network Protocols**
- **Linux Basics for Hackers**
- **Network Vulnerability Assessment**

### Reverse Engineering
- **Ghidra Book** - RE with Ghidra
- **Malware Data Science**
- **Evading EDR**

### Cryptography
- **Hash Crack** - Password cracking reference
- **Implementing Cryptography Using Python**

### Scripting
- **Bash Cookbook**
- **PowerShell Cookbook**
- **Python Crash Course**

## Configuration

### Chunk Size

Edit `agent/agent_black/knowledge/ingest.py`:

```python
CHUNK_SIZE = 500      # Characters per chunk
CHUNK_OVERLAP = 50    # Overlap between chunks
```

Smaller chunks = more precise retrieval but may lose context
Larger chunks = more context but less precise

### Embedding Model

Default is `nomic-embed-text`. Alternatives:
```python
EMBED_MODEL = "nomic-embed-text"  # Default, good balance
# EMBED_MODEL = "mxbai-embed-large"  # Higher quality, slower
# EMBED_MODEL = "all-minilm"  # Faster, lower quality
```

### Number of Results

```python
TOP_K = 5  # Number of chunks to retrieve per query
```

## Troubleshooting

### "Ollama connection failed"

Make sure Ollama is running:
```bash
ollama serve
```

And has the embedding model:
```bash
ollama pull nomic-embed-text
```

### "No documents found"

Check that PDFs are in the right folder:
```bash
ls agent/agent_black/knowledge/pdfs/
```

### "PDF extraction failed"

Some PDFs are image-based (scanned). Try OCR or find text-based versions.

### Database corruption

Delete and rebuild:
```bash
rm -rf agent/agent_black/knowledge/vector_db
python ingest.py
```

### Memory issues with large libraries

Process in batches or use a machine with more RAM. The embedding process is memory-intensive.

## Best Practices

1. **Organize by topic** - Use subfolders for different categories
2. **Quality over quantity** - Better to have 10 good books than 100 mediocre ones
3. **Keep it relevant** - Security-focused content works best
4. **Update regularly** - Re-ingest when you add new materials
5. **Test queries** - Verify the knowledge is retrievable

## Privacy Note

All processing happens locally:
- ChromaDB stores embeddings on your disk
- Ollama runs embeddings locally
- No data sent to external servers
- Your books stay on your machine
