# Agent BLACK Documentation

Agent BLACK is an AI-powered security assistant for LANTERN.

## Setup Guides

| Guide | Description |
|-------|-------------|
| [SETUP.md](SETUP.md) | **Start here** - Installation, configuration, quick start |
| [KNOWLEDGE.md](KNOWLEDGE.md) | Setting up the knowledge base with your security PDFs |
| [REMOTE.md](REMOTE.md) | Remote Kali host for hash cracking, WiFi, HackRF |

## Quick Start

```bash
pip install -e .
black --help
```

## Commands

| Command | Description |
|---------|-------------|
| `black` | Interactive chat (default) |
| `black chat` | Interactive chat mode |
| `black overwatch` | Situational awareness mode |
| `black overwatch --snapshot` | One-time analysis of current state |
| `black overwatch --watch` | Continuous monitoring with alerts |
| `black autonomous <target>` | Autonomous pentesting |
| `black pwn` | PWN/CTF utilities |
| `black status` | Check agent status |

## Requirements
- Python 3.10+
- Local GGUF model OR [Ollama](https://ollama.ai) for AI features
- Security PDFs for knowledge base (optional)
- Remote Kali host for advanced attacks (optional)

## Features

### Chat Mode
Natural language interface to LANTERN:
```
[YOU] > scan https://target.com for SQL injection
[YOU] > what modules should I use for API testing?
[YOU] > analyze these results
```

### Overwatch Mode
Situational awareness - monitors terminals, files, and tools:
```bash
black overwatch --snapshot       # One-time analysis
black overwatch --watch          # Continuous monitoring
black overwatch --watch --llm    # With AI-powered suggestions
```

**Watch Mode detects:**
- Flags (`flag{`, `ctf{`, `htb{`)
- Successful exploits (sessions, shells)
- Errors (connection refused, auth failed)
- SQL injection confirmations
- Privilege escalation

### Autonomous Mode
AI-driven scanning:
```bash
black autonomous https://target.com "find SQL injection vulnerabilities"
```

### Knowledge Base (RAG)
Learn from your security books:
- Web Application Hacker's Handbook
- OSCP materials
- Nmap, Metasploit guides
- Any PDF you add

### Remote Attacks
Execute on remote Kali host:
- Hash cracking (john, hashcat)
- WiFi attacks (aircrack-ng)
- RF attacks (HackRF)
- Any tool available on Kali

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/black.py` | Chat mode entry point |
| `scripts/black_overwatch.py` | Overwatch/Watch mode |
| `scripts/black_autonomous.py` | Autonomous scanning |
| `scripts/black_pwn.py` | CTF/PWN utilities |
| `agent_black/knowledge/ingest.py` | Ingest PDFs into knowledge base |
| `agent_black/knowledge/rag.py` | Query the knowledge base |

## Directory Structure

```
agent/
├── cli.py                # Unified CLI entry point
├── agents/
│   ├── base.py           # Base agent class
│   └── agent_black.py    # Main AgentBlack class
├── agent_black/
│   ├── knowledge/        # 21 knowledge documents
│   │   ├── pdfs/         # Add your PDFs here
│   │   ├── agent_brain.md
│   │   ├── decision_trees.md
│   │   ├── autonomous_reasoning.md
│   │   └── *.json/md     # Static knowledge files
│   ├── models/           # Local GGUF models
│   ├── overwatch_reports/ # Saved overwatch analyses
│   └── auto_learn.py     # Auto-learning system
├── scripts/              # Feature scripts
├── docs/                 # This documentation
└── requirements.txt
```

## Troubleshooting

1. Check Ollama is running: `curl http://localhost:11434/api/tags`
2. Check model is pulled: `ollama list`
3. Check local model exists: `ls agent/agent_black/models/*.gguf`
4. Check status: `black status`
