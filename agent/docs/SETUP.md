# Agent BLACK Setup Guide

Agent BLACK is an AI-powered security assistant that works alongside LANTERN. It provides natural language scanning, situational awareness, autonomous operation, and intelligent analysis.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Requirements](#requirements)
3. [Platform Support](#platform-support)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Knowledge Base Setup](#knowledge-base-setup)
7. [Running Agent BLACK](#running-agent-black)
8. [Overwatch Mode](#overwatch-mode)
9. [Advanced Features](#advanced-features)
10. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# From the LANTERNv2.0 root directory
pip install -e .

# Check status
black status

# Start chatting with Agent BLACK
black chat
```

That's it for basic usage. Read on for full setup with AI and knowledge base.

---

## Requirements

### Minimum Requirements
- Python 3.10+
- LANTERN installed and working

### For AI Features (Recommended)
- [Ollama](https://ollama.ai) - Local LLM server
- 8GB+ RAM for 7B models
- GPU optional but speeds up inference

### For Knowledge Base (Optional)
- Additional Python packages (see [Knowledge Base Setup](#knowledge-base-setup))
- Your security PDFs/books

### For Remote Attacks (Optional - Windows users)
- SSH access to a Kali Linux host
- HackRF hardware (for RF attacks)

---

## Platform Support

Agent BLACK works on **all platforms** but with different capabilities:

### Linux (Kali, Arch, Ubuntu, Debian, etc.)

**You can run everything locally!** No remote host needed.

If you're on Linux, Agent BLACK automatically detects this and runs tools locally:
- Hash cracking (john, hashcat) - runs on your machine
- WiFi attacks (aircrack-ng) - runs on your machine
- HackRF/SDR - runs on your machine
- All other commands - runs locally

Just install the tools you need:
```bash
# Arch Linux
sudo pacman -S john hashcat aircrack-ng hackrf

# Debian/Ubuntu/Kali
sudo apt install john hashcat aircrack-ng hackrf
```

### Windows / macOS

For advanced attacks (WiFi, hash cracking with GPU, HackRF), you have two options:

1. **Remote Kali Host** (Recommended)
   - Set up a Kali VM or Raspberry Pi
   - Configure SSH access
   - Agent BLACK executes commands remotely

2. **WSL2 (Windows only)**
   - Install Kali in WSL2
   - Some tools work, but WiFi/HackRF may not

### How It Works

Agent BLACK automatically detects your platform:
```python
agent.is_linux      # True on Linux
agent.local_mode    # True if Linux + no remote host configured
```

When you run a command like `hackrf scan`:
- **Linux without remote host**: Runs `hackrf_sweep` locally
- **Linux with remote host**: Runs via SSH on remote host
- **Windows/macOS with remote host**: Runs via SSH on remote host
- **Windows/macOS without remote host**: Returns error (tool not available)

---

## Installation

### Step 1: Install Agent Dependencies

```bash
cd agent
pip install -r requirements.txt
```

### Step 2: Install Ollama (for AI features)

**Windows:**
Download from https://ollama.ai/download

**Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**macOS:**
```bash
brew install ollama
```

### Step 3: Pull an LLM Model

```bash
# Start Ollama service
ollama serve

# In another terminal, pull a model
ollama pull mistral      # 7B model, good balance
# OR
ollama pull dolphin-mistral  # Uncensored variant
# OR
ollama pull llama2       # Alternative
```

### Step 4: Pull the Embedding Model (for knowledge base)

```bash
ollama pull nomic-embed-text
```

---

## Configuration

Agent BLACK can be configured via environment variables or a YAML config file.

### Environment Variables

```bash
# LLM Settings
export BLACK_OLLAMA_HOST=localhost
export BLACK_OLLAMA_PORT=11434
export BLACK_OLLAMA_MODEL=mistral

# Remote Kali Host (for hash cracking, WiFi, HackRF)
export BLACK_KALI_HOST=192.168.1.100
export BLACK_KALI_USER=kali
export BLACK_KALI_PORT=22

# GPU Host (for hashcat)
export BLACK_GPU_HOST=192.168.1.50
export BLACK_GPU_USER=user
```

### Config File (Optional)

Create `agent/config/config.yaml`:

```yaml
# LLM Configuration
ollama:
  host: localhost
  port: 11434
  model: mistral

# Remote Kali Host
kali:
  host: 192.168.1.100
  user: kali
  port: 22

# GPU Host for hashcat
gpu:
  host: 192.168.1.50
  user: user
```

---

## Knowledge Base Setup

Agent BLACK can learn from security PDFs, books, and documentation using RAG (Retrieval Augmented Generation).

### Step 1: Install Knowledge Base Dependencies

```bash
pip install langchain langchain-community chromadb pymupdf rich
```

### Step 2: Add Your PDFs

Place your security PDFs in `agent/agent_black/knowledge/pdfs/`:

```
agent/agent_black/knowledge/pdfs/
├── penetration_testing/
│   ├── OSCP_Guide.pdf
│   ├── Web_App_Hackers_Handbook.pdf
│   └── Metasploit_Guide.pdf
├── reverse_engineering/
│   ├── Ghidra_Book.pdf
│   └── Malware_Analysis.pdf
└── network_security/
    ├── Nmap_Cookbook.pdf
    └── Wireshark_Guide.pdf
```

Recommended resources:
- Web Application Hacker's Handbook
- OSCP Study Materials
- Penetration Testing books
- Nmap, Burp Suite, Metasploit guides
- Hash cracking documentation
- Reverse engineering guides (Ghidra, IDA)

### Step 3: Run Ingestion

```bash
cd agent/agent_black/knowledge

# Make sure Ollama is running with nomic-embed-text
ollama pull nomic-embed-text

# Ingest all documents
python ingest.py
```

This creates a local vector database that Agent BLACK uses to answer questions with relevant context from your books.

### Step 4: Verify

```bash
python rag.py
```

This shows how many chunks are indexed and runs a test query.

---

## Running Agent BLACK

### Available Commands

```bash
black                # Interactive chat (default)
black chat           # Interactive chat mode
black overwatch      # Situational awareness mode
black autonomous     # Autonomous pentesting
black pwn            # PWN/CTF utilities
black status         # Check agent status
```

### Interactive Chat Mode

```bash
black chat
```

This starts an interactive session where you can:
- Ask security questions
- Run LANTERN scans via natural language
- Analyze results
- Get exploit guidance

### Example Commands

```
[YOU] > scan https://target.com for SQL injection
[YOU] > what modules should I use for API testing?
[YOU] > crack this hash: 5f4dcc3b5aa765d61d8327deb882cf99
[YOU] > help
[YOU] > status
```

### Programmatic Usage

```python
from agents.agent_black import AgentBlack
import asyncio

agent = AgentBlack(load_model=True)

# Check status
print(agent.get_status())

# Ask a question
response = asyncio.run(agent.think("How do I test for SSRF?"))
print(response)

# Plan a scan
plan = asyncio.run(agent.plan_scan("Full security audit of https://target.com"))
print(plan)
```

---

## Overwatch Mode

Overwatch provides situational awareness by monitoring your entire work environment.

### Snapshot (One-Time Analysis)

```bash
black overwatch --snapshot
```

Takes a snapshot of:
- All open terminals (commands, output, errors)
- Recent report files
- Running security tools
- Clipboard contents

Automatically saves to `agent/agent_black/overwatch_reports/`.

### Watch Mode (Continuous Monitoring)

```bash
black overwatch --watch
```

Continuously monitors for:
- Flags (`flag{`, `ctf{`, `htb{`, `picoctf{`)
- Successful exploits (sessions, shells, root access)
- Errors (connection refused, permission denied, auth failed)
- SQL injection confirmations
- Privilege escalation indicators

**Options:**
```bash
black overwatch --watch --interval 5    # Check every 5 seconds (default: 10)
black overwatch --watch --llm           # Enable AI-powered suggestions
```

### Interactive Mode

```bash
black overwatch
black overwatch --llm    # With AI analysis
```

Commands in interactive mode:
```
[OVERWATCH] > status     # Analyze current situation
[OVERWATCH] > refresh    # Re-scan all terminals
[OVERWATCH] > help <question>   # Ask about your situation
[OVERWATCH] > quit       # Exit
```

### What Watch Mode Detects

| Severity | Patterns |
|----------|----------|
| Critical | Flags, sessions opened, credentials found, root/SYSTEM shell |
| Warning | Permission denied, connection refused, auth failed |
| Info | SQL syntax errors, stack traces, server errors |

### Terminal Sources (Universal)

Overwatch reads from multiple sources depending on your system:

| Source | Location | Platform |
|--------|----------|----------|
| Bash history | `~/.bash_history` | Linux/macOS |
| Zsh history | `~/.zsh_history` | Linux/macOS |
| Fish history | `~/.local/share/fish/fish_history` | Linux/macOS |
| PowerShell | `~/AppData/.../PSReadLine/ConsoleHost_history.txt` | Windows |
| IDE terminals | `~/.cursor/projects/*/terminals/` | Cursor IDE |
| Custom logs | `~/.agent_black/terminal_logs/` | Any |

**For detailed terminal output (recommended):**

Add to your shell profile (`~/.bashrc`, `~/.zshrc`):
```bash
export BLACK_TERMINAL_LOGS="$HOME/.agent_black/terminal_logs"
mkdir -p "$BLACK_TERMINAL_LOGS"

script -q -a "$BLACK_TERMINAL_LOGS/session_$(date +%Y%m%d).log"
```

Or set the environment variable to point to any directory with `.log` files.

---

## Advanced Features

### Remote Kali Execution

Configure a remote Kali host for:
- Password cracking with john/hashcat
- WiFi attacks with aircrack-ng
- HackRF/SDR operations

```bash
export BLACK_KALI_HOST=192.168.1.100
export BLACK_KALI_USER=kali
```

Then in chat:
```
[YOU] > crack hashes
[YOU] > hackrf scan 433mhz
[YOU] > wifi scan
```

### Knowledge Queries

Once your knowledge base is set up:
```
[YOU] > how do I bypass WAF for SQL injection?
[YOU] > what are common SSRF payloads?
[YOU] > explain JWT none algorithm attack
```

Agent BLACK will search your ingested books and provide answers with sources.

### Attack Planning

```
[YOU] > I found an SSRF, what should I try next?
[YOU] > plan attack chain for e-commerce site
[YOU] > what exploitation options for LFI?
```

---

## Troubleshooting

### "No LLM available - running in keyword mode"

Ollama isn't running or model isn't pulled:
```bash
ollama serve       # Start Ollama
ollama pull mistral  # Pull model
```

### "Vector database not found"

Run the knowledge ingestion:
```bash
cd agent/agent_black/knowledge
python ingest.py
```

### "No remote host configured"

Set the Kali host environment variable:
```bash
export BLACK_KALI_HOST=192.168.1.100
```

### Slow responses

- Use a smaller model: `ollama pull tinyllama`
- Reduce knowledge base size
- Run Ollama on a GPU

### ImportError for langchain/chromadb

Install knowledge base dependencies:
```bash
pip install langchain langchain-community chromadb pymupdf
```

---

## Next Steps

- [Knowledge Base Guide](KNOWLEDGE.md) - Deep dive into RAG setup
- [Remote Attacks Guide](REMOTE.md) - WiFi, HackRF, hash cracking
- [API Reference](API.md) - AgentBlack class documentation

---

## Support

For issues, check:
1. Ollama is running: `curl http://localhost:11434/api/tags`
2. Model is available: `ollama list`
3. Dependencies installed: `pip list | grep langchain`
