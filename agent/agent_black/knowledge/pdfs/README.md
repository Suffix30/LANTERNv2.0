# Agent BLACK Knowledge PDFs

Add your security PDFs here to give Agent BLACK a brain.

## Recommended Resources

- Penetration testing books (OSCP, Metasploit, etc.)
- Web hacking guides (Web Application Hacker's Handbook, Bug Bounty books)
- Tool documentation (Nmap Cookbook, Burp Suite, etc.)
- Exploit development (Shellcoder's Handbook, Black Hat Python)
- Reverse engineering (Ghidra, IDA Pro guides)
- Network security (Wireshark, tcpdump guides)
- Hash cracking (hashcat, John the Ripper docs)

## How to Use

1. Add PDFs, TXT, or MD files to this folder (subfolders supported)

2. Install dependencies:
   ```
   pip install langchain langchain-community chromadb pymupdf ollama rich
   ```

3. Make sure Ollama is running with the embedding model:
   ```
   ollama pull nomic-embed-text
   ollama serve
   ```

4. Run the ingestion:
   ```
   cd agent/agent_black/knowledge
   python ingest.py
   ```

5. Agent BLACK will now use this knowledge for RAG queries

## Notes

- The vector database is stored in `vector_db/` (gitignored)
- Larger PDFs take longer to process
- You can re-run ingestion anytime with `--force` to rebuild
- The embedding model runs locally via Ollama (no API keys needed)
