# Agent BLACK

Agent BLACK is an AI-powered security companion for LANTERN. It provides natural language control, situational awareness, autonomous scanning, and intelligent analysis.

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
| `black autonomous` | Autonomous pentesting |
| `black pwn` | PWN/CTF utilities |
| `black obsidian` | Obsidian vault integration |
| `black status` | Check agent status |

## Features

### Chat Mode
Natural language interface for LANTERN:
```bash
black chat
```
- "Scan target.com for SQL injection"
- "What modules should I use for API testing?"
- "Analyze these scan results"

### Overwatch Mode (Situational Awareness)
Agent BLACK can monitor your entire work environment:
```bash
black overwatch --snapshot       # One-time analysis
black overwatch --watch          # Continuous monitoring with proactive alerts
black overwatch --watch --llm    # Watch mode with AI-powered suggestions
black overwatch --interval 5     # Check every 5 seconds
```

**What Overwatch monitors:**
- Shell history (bash, zsh, fish, PowerShell)
- IDE terminals (Cursor, VS Code)
- Custom terminal logs (configurable)
- Browser tabs (via optional extension)
- Recent report files
- Running security tools
- Clipboard contents

**Works on any system:**
- Linux (Kali, Ubuntu, Arch) - reads shell history
- Windows - reads PowerShell history
- macOS - reads zsh/bash history
- Any IDE with terminal logging

**What it detects:**
- Flags (`flag{`, `ctf{`, `htb{`)
- Successful exploits (sessions, shells)
- Errors (connection refused, auth failed)
- SQL injection confirmations
- Privilege escalation

### Watch Mode (Proactive Alerts)
Continuous monitoring that alerts you when something important happens:
```bash
black overwatch --watch
```
- Beeps when issues or opportunities detected
- Groups findings by severity (critical/warning/info)
- With `--llm`, provides AI-suggested next steps
- Tracks seen alerts to avoid repetition

### Autonomous Mode
Let Agent BLACK plan and execute scans:
```bash
black autonomous https://target.com "find SQL injection vulnerabilities"
```

### PWN Mode
CTF and exploitation utilities:
```bash
black pwn
```

### Obsidian Integration (Beta)
> **Note:** Under active development. Core features work but may evolve.

Full integration with Obsidian for note-taking, writeups, and knowledge management:
```bash
black obsidian init ~/Documents           # Create security vault
black obsidian target Photobomb --platform HTB --ip 10.10.11.182
black obsidian note "found command injection in download feature"
black obsidian stats                       # Vault statistics
```

**Auto-export to vault:**
```bash
black overwatch --snapshot --obsidian     # Export session to vault
```

**Vault structure created:**
```
Security Vault/
├── Targets/          # HTB, THM, VulnLab, Bug Bounty
├── Writeups/         # Organized by platform
├── Methodology/      # Web, Network, AD, Privesc
├── Payloads/         # SQLi, XSS, SSRF, etc.
├── Tools/            # Tool notes including LANTERN
├── Cheatsheets/
├── LANTERN Reports/  # Auto-exported scans
├── Overwatch Sessions/
└── Templates/        # Target, Finding, Writeup templates
```

## Models

### Local GGUF Models (Recommended)
Drop a `.gguf` file into `agent_black/models/`:
```
agent_black/models/
└── dolphin-mistral-7b.gguf
```

### Ollama
```bash
ollama serve
ollama pull mistral
```

## Knowledge Base

Agent BLACK comes with 21 knowledge documents covering:
- LANTERN integration (62 modules, all features)
- Attack methodologies
- Payload mutation strategies
- Decision trees for common scenarios
- Self-improvement systems

### Knowledge Files
```
agent_black/knowledge/
├── agent_brain.md          # Identity and capabilities
├── operating_rules.md      # Behavioral guidelines
├── goal_loop.md            # Continuous operation
├── autonomous_reasoning.md # OODA loop, decision making
├── decision_trees.md       # Step-by-step attack paths
├── lantern_integration.md  # Full LANTERN control
├── payload_mutation.md     # WAF bypass strategies
├── self_improvement.md     # Learning and adaptation
└── ... (21 total)
```

## Requirements

- Python 3.10+
- LANTERN installed
- (Optional) Ollama or local GGUF model for AI features

## Safety

Use only on targets you own or have explicit permission to test.

## Documentation

- [Setup Guide](docs/SETUP.md) - Full installation instructions
- [Knowledge Guide](docs/KNOWLEDGE.md) - RAG and PDF ingestion
- [Remote Attacks](docs/REMOTE.md) - Kali host configuration
