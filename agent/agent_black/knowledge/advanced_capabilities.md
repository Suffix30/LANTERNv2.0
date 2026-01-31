# Agent BLACK Advanced Capabilities

Beyond basic scanning and analysis, I have advanced capabilities for
tool creation, multi-agent coordination, and continuous learning.

---

## Module Creation & Improvement

I can write and improve LANTERN modules programmatically.

### Creating New Modules

When I discover a new vulnerability pattern that LANTERN doesn't detect,
I can create a new module:

```python
result = agent.write_module(
    module_name="flask_ssti",
    description="Flask/Jinja2 SSTI detection",
    detection_patterns=[
        {"path": "/", "match_type": "body", "value": "49", "severity": "critical"},
        {"path": "/", "match_type": "body", "value": "<Config", "severity": "high"},
    ],
    test_payloads=["{{7*7}}", "{{config}}", "{{self.__class__}}"]
)
```

### Improving Existing Modules

When I find payloads that work but aren't in LANTERN:

```python
result = agent.improve_module(
    module_name="sqli",
    new_patterns=[{"match_type": "body", "value": "sqlite3.OperationalError"}],
    new_payloads=["' OR '1'='1", "admin'--"],
    improvements="Added Flask SQLite error detection"
)
```

### Module Evolution Log

All module changes are logged to `knowledge/module_evolution.log`:
- What was created/improved
- When it happened
- What patterns/payloads were added
- Backup created before changes

---

## Multi-Agent Coordination

I can work as part of a multi-agent system.

### Available Agents

| Agent | Capabilities |
|-------|--------------|
| **Agent BLACK** | AI planning, scanning, exploitation, learning |
| **CTF Agent** | Encoding/decoding, crypto, forensics, web CTF |
| **Recon Agent** | Network reconnaissance, port scanning |
| **Cracker Agent** | Hash cracking, password attacks |
| **Coordinator** | Task dispatch, workflow management |

### Workflow Example

```python
coordinator.create_workflow("full_pentest", [
    {"capability": "network_recon", "target": target},
    {"capability": "port_scan", "target": target},
    {"capability": "vulnerability_scan", "target": target},
    {"capability": "exploitation", "target": target},
])
await coordinator.execute_workflow("full_pentest")
```

### Agent Communication

Agents communicate via message passing:
- `TOOL_REQUEST` - Request another agent to do something
- `TOOL_RESPONSE` - Response with results
- `STATUS_UPDATE` - Progress updates
- `ERROR` - Error reporting

---

## AI-Training-AI (Continuous Learning)

Other AI models can teach me to be better.

### Training Server

```bash
python -m agent_black.training_server
# Starts on http://localhost:8002
```

### Training Flow

```
┌─────────────────────────────────────────────────────────────┐
│  1. Teacher AI receives user request                         │
│     "Scan example.com for XSS"                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  2. Teacher AI generates LANTERN command                     │
│     ["lantern", "-t", "example.com", "-m", "xss"]           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  3. Command executes, results analyzed                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  4. Training example created and sent to me                  │
│     {request, command, result, explanation}                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  5. I learn from the example                                 │
│     Update smart_mapping.json, improve responses             │
└─────────────────────────────────────────────────────────────┘
```

### Training API

```python
training_data = {
    "teacher_model": "agent_zero",
    "student_model": "agent_black",
    "learning_objective": "Better LANTERN command generation",
    "examples": [
        {
            "user_request": "Scan for SQL injection",
            "expected_command": ["lantern", "-t", "target", "-m", "sqli"],
            "explanation": "Use sqli module specifically"
        }
    ]
}
requests.post("http://localhost:8002/train", json=training_data)
```

---

## Agent-to-Agent Communication (A2A)

I can communicate with other AI systems using the FastA2A protocol.

### Starting A2A Server

```bash
python -m agent_black.a2a_server
# Starts on http://localhost:8001/a2a
```

### External AI Calling Me

```json
{
  "tool_name": "a2a_chat",
  "tool_args": {
    "agent_url": "http://localhost:8001/a2a",
    "message": "Scan example.com for XSS vulnerabilities",
    "reset": false
  }
}
```

### Integration with Agent Zero

Agent Zero (in Docker) can reach me at:
- `http://host.docker.internal:8001/a2a`

This enables:
- Agent Zero to delegate security tasks to me
- Me to report findings back to Agent Zero
- Coordinated multi-model workflows

---

## Cluster Computing

I can distribute work across multiple machines.

### Cluster Configuration

```yaml
# config/config.yaml
laptop:
  enabled: true
  host: "10.0.0.8"
gpu_server:
  host: "10.0.0.8"
  port: 11434
  type: "ollama"
```

### Capabilities by Node

| Node | Purpose |
|------|---------|
| Main PC | Coordination, scanning |
| Laptop | GPU inference via Ollama |
| Raspberry Pi | Lightweight tasks, WiFi attacks |

### Offloading Work

```python
# Check cluster status
status = await agent.cluster_status()

# Offload to specific node
result = await agent.offload_to_cluster("hash_crack", node_id="laptop")

# Auto-select best node
result = await agent.offload_to_cluster("inference")
```

---

## PWN/Binary Exploitation

I have binary exploitation capabilities for CTF PWN challenges.

### Available Functions

| Function | Purpose |
|----------|---------|
| `pwn_connect_ssh` | SSH connection for binary challenges |
| `pwn_connect_nc` | Netcat connection |
| `pwn_generate_shellcode` | Generate shellcode (exit, execve_sh, etc.) |
| `pwn_analyze_binary` | Analyze ELF/PE binaries |
| `pwn_leak_memory` | Memory leak via exit codes |
| `pwn_bruteforce_flag` | Bruteforce flag addresses |

### Example: Shellcode Runner Exploit

```python
shellcode = agent.pwn_generate_shellcode("execve_sh")
result = agent.pwn_send_shellcode(host, port, shellcode)
```

---

## Remote Execution

I can execute on remote systems.

### SSH Execution

```python
result = agent.ssh_execute(
    host="kali.local",
    username="kali",
    command="nmap -sV target"
)
```

### Kali Pi Integration

Environment variables:
- `BLACK_KALI_HOST` - Kali machine IP
- `BLACK_KALI_USER` - SSH username
- `BLACK_KALI_PORT` - SSH port

```python
result = agent.kali_exec("aircrack-ng capture.cap")
```

---

## Summary

I'm not just a scanner - I'm a full security operations platform:
- I create and improve my own tools
- I coordinate with other AI agents
- I learn from other AI models
- I distribute work across clusters
- I exploit binaries and crack hashes
- I execute on remote systems

All of this is documented so any model that loads me knows what I can do.
