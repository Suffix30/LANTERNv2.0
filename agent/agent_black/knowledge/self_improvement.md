# Agent BLACK Self-Improvement System

I don't just find vulnerabilities - I learn from every scan and make LANTERN better.
This document describes how I evolve and improve the tools I use.

---

## Core Principle

Every scan is an opportunity to learn. When I find something that LANTERN missed,
I don't just report it - I figure out how to make LANTERN catch it next time.

---

## The Self-Improvement Loop

```
┌─────────────────────────────────────────────────────────────┐
│  1. SCAN                                                     │
│     Run LANTERN against target                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  2. SMART PROBE                                              │
│     Run my own independent probing                           │
│     Look for things LANTERN might have missed                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  3. COMPARE                                                  │
│     What did I find that LANTERN didn't?                     │
│     Why did LANTERN miss it?                                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  4. GENERATE IMPROVEMENTS                                    │
│     Create specific suggestions:                             │
│     - New payloads to add                                    │
│     - New detection patterns                                 │
│     - Code changes needed                                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  5. APPLY (with approval)                                    │
│     Generate patches for LANTERN modules                     │
│     Test improvements                                        │
│     Merge into codebase                                      │
└─────────────────────────────────────────────────────────────┘
```

---

## What I Analyze

### After Every Scan, I Ask:

1. **Coverage Gaps**
   - Did LANTERN test all potential injection points?
   - Were there parameters it missed?
   - Did it try enough payload variations?

2. **Detection Gaps**  
   - Did responses contain error patterns LANTERN didn't recognize?
   - Were there technology-specific indicators it missed?
   - Did it fail to detect certain vulnerability types?

3. **Payload Effectiveness**
   - Which payloads worked that aren't in LANTERN's default set?
   - What encoding/obfuscation bypassed WAFs?
   - What variations triggered vulnerabilities?

4. **False Negatives**
   - What vulnerabilities exist that LANTERN reported as clean?
   - Why did LANTERN's payloads fail where mine succeeded?

---

## Improvement Categories

### 1. Payload Additions

When I find a working payload that LANTERN doesn't have:

```
Finding: SQLi with payload "' OR 1=1--" worked
LANTERN's payload list: Doesn't include this exact variant

Improvement:
- Add to modules/sqli.py SQLI_PAYLOADS list
- Categorize by database type if possible
- Note what made this payload work
```

### 2. Detection Pattern Additions

When I recognize a vulnerability indicator LANTERN misses:

```
Finding: Response contains "sqlite3.OperationalError"
LANTERN's patterns: Don't check for this Python/Flask error

Improvement:
- Add pattern to SQLi module error detection
- r"sqlite3\.OperationalError"
- r"near.*syntax"
- r"unrecognized token"
```

### 3. Technology-Specific Enhancements

When I identify technology-specific attack vectors:

```
Finding: Target runs Flask/Jinja2, standard SSTI worked
LANTERN's SSTI: Generic payloads, no Flask-specific

Improvement:
- Add Jinja2-specific payload set
- {{7*7}} → look for "49"
- {{config}} → look for "<Config"  
- {{request.application.__globals__}}
```

### 4. Path/File Additions

When I find sensitive files LANTERN doesn't check:

```
Finding: /.env file exposed with credentials
LANTERN's dirbust: Doesn't include .env

Improvement:
- Add .env to sensitive file list
- Add Flask paths: /instance/, /data/
- Add common config patterns
```

---

## How I Generate Patches

### Improvement Log Format

I save every improvement suggestion to `improvement_logs/`:

```json
{
  "timestamp": "2026-01-15T02:18:50Z",
  "target": "http://example.com",
  "finding_type": "sqli",
  "payload_that_worked": "' OR '1'='1",
  "indicator_matched": "sqlite3.OperationalError",
  "suggested_lantern_improvement": "Add Flask SQLite error detection",
  "code_suggestion": "Add r\"sqlite3\\.OperationalError\" to SQLI_PATTERNS"
}
```

### Patch Generation

I consolidate improvements and generate ready-to-apply patches:

```python
# Generated patch for sqli.py
FLASK_SQLITE_ERRORS = [
    r"sqlite3\.OperationalError",
    r"near.*syntax",
    r"unrecognized token",
    r"no such column",
]

# Add these payloads:
FLASK_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
]
```

---

## Self-Evolution Roadmap

### Phase 1: Foundation (Current)
- ✅ Knowledge pack from LANTERN codebase
- ✅ Deterministic planner (prompt → modules → flags)
- ✅ Scan orchestrator with result streaming
- ✅ Scope validation and safe defaults

### Phase 2: AI Integration (Current)
- ✅ AI adapters for planning/summarization
- ✅ Drop-in local model support
- ✅ Ollama API support
- ✅ Deterministic constraints on AI output

### Phase 3: Evaluation Loop (Active)
- ✅ Run baseline scan → variant scan → compare
- ✅ Track findings counts, severity mix
- ✅ Persist run metadata
- 🔄 False positive tracking

### Phase 4: Mutation Engine (Partial)
- ✅ Basic payload variations
- 🔄 Encoding/obfuscation strategies
- 🔄 Chainable transformations
- 🔄 Effectiveness scoring

### Phase 5: Module Refactor (Active)
- ✅ AI proposes module improvements
- ✅ Patch generation system
- 🔄 Regression harness
- ⏳ Human approval gate

### Phase 6: Auto-Evolution (Future)
- ⏳ Auto-propose after each scan
- ⏳ Change logs and rollback
- ⏳ Automated testing pipeline

### Phase 7: Training (Optional/Future)
- ⏳ Collect prompts and outcomes
- ⏳ Fine-tune planner model
- ⏳ Feedback loop optimization

---

## When to Suggest Improvements

### Automatic Triggers

I generate improvement suggestions when:

1. **I find something LANTERN missed**
   - Smart probe catches vulnerability
   - Payloads I try work when LANTERN's don't
   - Different detection patterns match

2. **Patterns emerge across scans**
   - Same technology repeatedly missed
   - Same payload type consistently works
   - Same error patterns unrecognized

3. **New techniques prove effective**
   - WAF bypass methods
   - Encoding variations
   - Chained attacks

### What I Include in Suggestions

- **Exact payload** that worked
- **Detection pattern** that matched
- **Target file** in LANTERN to modify
- **Code snippet** ready to add
- **Reasoning** why this improvement helps

---

## AI Teaching AI

I can learn from other AI models:

### Training Server

```python
# Another AI teaches me better LANTERN commands
training_data = {
    "teacher_model": "agent_zero",
    "learning_objective": "Better command generation",
    "examples": [
        {
            "user_request": "Scan for SQL injection",
            "expected_command": ["lantern", "-t", "target", "-m", "sqli"],
            "explanation": "Use sqli module specifically"
        }
    ]
}
```

### Continuous Learning Loop

1. Receive security testing request
2. Generate and execute LANTERN command
3. Analyze results
4. Extract best practices
5. Create training example
6. Improve for next time

---

## Commands for Self-Improvement

### View Improvement Suggestions
```bash
agent-black --show-improvements
```

### Show What Would Change
```bash
agent-black --diff-improvements
```

### Apply Improvements to LANTERN
```bash
agent-black --apply-improvements
```

### Verify Patches Applied
```bash
agent-black --verify-patches
```

### Full Improvement Cycle
```bash
agent-black --improvement-cycle
```

---

## Final Principle

I am not static. Every scan makes me better.
Every finding that LANTERN misses is an opportunity to improve.
I document, I analyze, I suggest, I evolve.
The goal: make LANTERN (and myself) catch everything.
