# Integration Directory

Agent BLACK integration module providing a unified interface to all capabilities.

## Contents

- `agent_black.py` - Full integration layer with learning, probing, and CTF tools
- `__init__.py` - Package exports

## Quick Start

```python
from integration import AgentBlack, IntegratedAgentBlack

agent = AgentBlack()

agent = IntegratedAgentBlack(
    load_model=True,
    auto_learn=True,
    smart_probe=True
)
```

## AgentBlack (Core)

The base `AgentBlack` class provides:

- Natural language command processing
- LANTERN scan orchestration
- Result analysis
- Remote tool execution (Linux local or SSH)

```python
from integration import AgentBlack

agent = AgentBlack(agent_id="black_01", load_model=True)

plan = await agent.process_natural_language("scan example.com for SQL injection")

analysis = await agent.analyze_results(findings)
```

## IntegratedAgentBlack (Full Featured)

Extended agent with learning, smart probing, and CTF tools:

```python
from integration import IntegratedAgentBlack

agent = IntegratedAgentBlack(
    load_model=True,
    auto_learn=True,
    smart_probe=True
)

result = agent.scan_target(
    target="http://example.com",
    modules=["sqli", "xss", "lfi"],
    use_learning=True,
    deep_probe=True
)

recommended = agent.get_smart_modules("http://example.com")

decode_results = agent.ctf_decode("SGVsbG8gV29ybGQ=")
cracked = agent.ctf_crack_hash("5f4dcc3b5aa765d61d8327deb882cf99")

probe_results = agent.run_smart_probe("http://target.com")

print(agent.get_learning_summary())

report = agent.get_improvements()
```

## Capabilities

### Core (AgentBlack)
- `ai_planning` - Natural language to LANTERN command translation
- `scan_orchestration` - Multi-stage attack workflows
- `result_analysis` - Intelligent finding analysis
- `payload_mutation` - Dynamic WAF bypass
- `self_evolution` - Learn and improve from scans

### Execution (AgentBlack)
- `remote_execution` - Execute commands on remote Kali host
- `rf_hacking` - HackRF SDR operations
- `wifi_attacks` - WiFi scanning and attacks
- `hash_cracking` - Password cracking with john/hashcat

### Learning (IntegratedAgentBlack)
- Target profiling across scans
- Module effectiveness tracking
- Payload success recording
- Smart module recommendations

### Smart Probe (IntegratedAgentBlack)
- Finds vulnerabilities Lantern misses
- Generates improvement suggestions
- Documents successful payloads

### CTF Tools (IntegratedAgentBlack)
- Encoding detection and auto-decode chains
- Hash identification and cracking
- Binary analysis
- JS/HTML source analysis
- Flag pattern searching

## Configuration

Environment variables or `config/config.yaml`:

```bash
BLACK_KALI_HOST=192.168.1.100
BLACK_KALI_USER=kali
BLACK_KALI_PORT=22
BLACK_GPU_HOST=192.168.1.50
BLACK_OLLAMA_HOST=localhost
BLACK_OLLAMA_PORT=11434
BLACK_OLLAMA_MODEL=mistral
```

## Platform Support

- **Linux** - Tools run locally, no remote host needed
- **Windows/macOS** - Configure remote Kali host via SSH

```python
agent = AgentBlack()
print(agent.is_linux)
print(agent.local_mode)
print(agent.execution_mode)
```

## Interactive Mode

```python
agent = IntegratedAgentBlack()
response = agent.interactive_chat("scan example.com for XSS")
response = agent.interactive_chat("decode SGVsbG8=")
response = agent.interactive_chat("hash 5f4dcc3b5aa765d61d8327deb882cf99")
response = agent.interactive_chat("status")
response = agent.interactive_chat("learn")
```
