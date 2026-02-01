# Agent BLACK Adaptive System

I continuously evolve and improve LANTERN's detection capabilities through an autonomous learning cycle.

---

## Core Components

### 1. Capability Registry

Every action I can take is registered with full introspection:

```
black capabilities
```

Each capability has:
- Name and description
- Required/optional parameters
- Category (scanning, execution, analysis, rf, wireless, cracking)
- Execution tracking and priority scoring

### 2. Multi-Provider LLM

I can use multiple LLM backends:
- **Ollama** - Local inference via Ollama server
- **Local GGUF** - Direct model loading via llama-cpp
- **Anthropic** - Claude API (requires ANTHROPIC_API_KEY)
- **OpenAI** - GPT-4 API (requires OPENAI_API_KEY)
- **DeepSeek** - DeepSeek API (requires DEEPSEEK_API_KEY)

Set provider via `BLACK_LLM_PROVIDER` environment variable.

### 3. Improvement Lineage

Every improvement I make is tracked with ancestry:

```
black lineage
black lineage --stones
```

Shows:
- Parent-child relationships
- Accuracy scores at each node
- Best-performing branch
- Stepping stones and breakthrough ancestors

### 4. Merit-Based Selection

When selecting which improvement branch to build on, I use weighted selection:
- Higher accuracy = higher selection probability
- Fewer children = exploration bonus
- Combines exploitation and exploration

### 5. Goal Management

Dynamic objective adaptation:

```
black goals
black goals --switch accuracy
black goals --switch coverage
black goals --history
```

Available goals:
- **accuracy** - Maximize detection accuracy
- **coverage** - Maximize vulnerability type coverage
- **precision** - Minimize false positives
- **recall** - Minimize false negatives
- **transfer** - Maximize cross-target generalization

### 6. Stepping Stones

I track and preserve less-performant improvements that led to breakthroughs:

```
black lineage --stones
```

Features:
- Identifies breakthrough ancestors (>5% accuracy jump)
- Marks leaf nodes for future exploration
- Prevents premature convergence on suboptimal solutions

### 7. Safety Validation

Hallucination and reward hacking detection:

```
black safety
black safety --flagged
```

Checks for:
- Suspicious test pass claims
- Unrealistic accuracy jumps
- Hardcoded success values
- Mocked results

### 8. Transfer Testing

Validates improvements generalize:

```
black transfer --module sqli
black transfer --target http://other-target.com
```

Tests:
- Cross-module transfer (does SQLi improvement help XSS?)
- Cross-target transfer (does it work on different apps?)

### 9. Detection Benchmark

Objective accuracy measurement:

```
black benchmark
black benchmark --tags injection
black benchmark --compare before.json after.json
```

Metrics:
- Precision, Recall, F1 Score
- Per-module accuracy
- Category breakdowns

### 10. Gap Analysis

When LANTERN misses vulnerabilities:

```python
from agent_black.smart_probe import run_gap_analysis
analysis = run_gap_analysis(target)
```

Produces:
- Root cause analysis
- Affected modules
- Implementation suggestions
- Code templates

### 11. Isolated Testing

Before applying any improvement:
1. Create sandbox copy
2. Apply patch
3. Run tests
4. Validate safety
5. Check transfer capability
6. Compare accuracy
7. Only apply if improved and safe

### 12. Adaptive Engine

The complete improvement cycle:

```
black adapt http://target.com
black adapt http://target.com --continuous 5
black adapt http://target.com --branch 3
black adapt --status
black adapt --full-status
```

Cycle phases:
1. LANTERN scan
2. Smart probe
3. Gap analysis
4. Generate improvements
5. Safety validation
6. Test and apply
7. Goal switching (if stagnating)

---

## Commands

### Adaptive Engine

```bash
black adapt <target>
black adapt <target> --continuous 5
black adapt <target> --branch 3
black adapt --status
black adapt --full-status
```

### Goal Management

```bash
black goals
black goals --switch accuracy
black goals --switch coverage
black goals --history
```

### Safety Validation

```bash
black safety
black safety --flagged
```

### Transfer Testing

```bash
black transfer --module sqli
black transfer --target http://other.com
```

### Lineage & Visualization

```bash
black lineage
black lineage --stones
black visualize --tree
black visualize --html
black visualize --progress
```

### Benchmark

```bash
black benchmark
black benchmark --tags injection
black benchmark --compare file1 file2
```

### Capabilities

```bash
black capabilities
```

---

## Adaptive Architecture Flow

```
    ┌──────────────────────────────────────────────────────────┐
    │                    ADAPTIVE ENGINE                        │
    └──────────────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    ▼
    ┌─────────┐         ┌─────────┐         ┌─────────┐
    │ Branch 1│         │ Branch 2│         │ Branch 3│
    │(Parent A)│         │(Parent B)│         │(Parent C)│
    └────┬────┘         └────┬────┘         └────┬────┘
         │                   │                   │
    ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
    │  SCAN   │         │  SCAN   │         │  SCAN   │
    │ TARGET  │         │ TARGET  │         │ TARGET  │
    └────┬────┘         └────┬────┘         └────┬────┘
         │                   │                   │
    ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
    │   GAP   │         │   GAP   │         │   GAP   │
    │ANALYSIS │         │ANALYSIS │         │ANALYSIS │
    └────┬────┘         └────┬────┘         └────┬────┘
         │                   │                   │
    ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
    │ SAFETY  │         │ SAFETY  │         │ SAFETY  │
    │  CHECK  │         │  CHECK  │         │  CHECK  │
    └────┬────┘         └────┬────┘         └────┬────┘
         │                   │                   │
    ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
    │TRANSFER │         │TRANSFER │         │TRANSFER │
    │  TEST   │         │  TEST   │         │  TEST   │
    └────┬────┘         └────┬────┘         └────┬────┘
         │                   │                   │
         └─────────┬─────────┴─────────┬────────┘
                   ▼                   │
         ┌─────────────────┐          │
         │  BEST BRANCH    │◀─────────┘
         │   SELECTED      │
         └────────┬────────┘
                  │
         ┌────────▼────────┐
         │ ADD TO LINEAGE  │
         │ (Archive Node)  │
         └─────────────────┘
```

### Selection Algorithm

```python
for each candidate:
    merit = sigmoid(accuracy_score)
    exploration_bonus = 1 / (1 + children_count)
    weight = merit * exploration_bonus

probability = normalize(weights)
parent = weighted_random_choice(probability)
```

### Lineage Structure

```
[initial]
├── imp_20260201_a1b2c3d4 (0.150)
│   ├── imp_20260201_e5f6g7h8 (0.200) ★ breakthrough
│   │   └── imp_20260201_x9y0z1a2 (0.250) ★ best
│   └── imp_20260201_i9j0k1l2 (0.180) → stepping stone
└── imp_20260201_m3n4o5p6 (0.120) → leaf (unexplored)
```

---

## Configuration

### Environment Variables

```bash
BLACK_LLM_PROVIDER=ollama
BLACK_OLLAMA_HOST=localhost
BLACK_OLLAMA_MODEL=mistral
BLACK_ANTHROPIC_MODEL=claude-3-5-sonnet-20241022
BLACK_OPENAI_MODEL=gpt-4o
BLACK_DEEPSEEK_MODEL=deepseek-chat
BLACK_AGENT_ROOT=/path/to/agent
```

### Files

```
agent/agent_black/
├── learned/
│   ├── improvement_lineage.json
│   ├── improvement_archive.json
│   ├── target_profiles.json
│   ├── module_effectiveness.json
│   ├── active_goals.json
│   ├── stepping_stones.json
│   └── safety_validations.json
├── adaptive_state/
│   ├── engine_state.json
│   └── generations.json
├── gap_analysis/
│   └── gap_analysis_*.json
├── transfer_results/
│   └── transfer_*.json
├── visualizations/
│   └── lineage_*.html
└── sandbox/
```

---

## Core Principles

1. **Open-Ended Exploration** - Multiple parallel branches exploring different improvement paths
2. **Archive of Agents** - All improvements preserved in lineage, not just best performers
3. **Stepping Stones** - Less-performant ancestors preserved when they lead to breakthroughs
4. **Empirical Validation** - All changes tested in sandbox before applying
5. **Safety-First** - Hallucination detection and reward hacking prevention
6. **Goal Switching** - Automatic adaptation when current goal stagnates
7. **Transfer Testing** - Verifies improvements generalize across modules and targets
8. **Merit-Based Selection** - Probabilistic parent selection balancing exploitation/exploration

---

## Integration with LANTERN

The adaptive system enhances LANTERN modules by:

1. **Adding Payloads** - New payloads that worked during probing
2. **Adding Patterns** - Detection patterns that caught vulnerabilities
3. **Improving Coverage** - Filling gaps in module coverage
4. **Tracking Effectiveness** - Knowing which modules work best
5. **Cross-Module Learning** - Improvements that help one module can transfer to others

All improvements are tracked, tested, validated for safety, and checked for transfer capability before integration.

---

## Autonomous Operation

For continuous improvement with branching exploration:

```bash
black adapt http://dvwa.local --continuous 10 --branch 3
```

This will:
1. Run 10 improvement generations
2. Explore 3 parallel branches each generation
3. Track cumulative accuracy gains
4. Automatically switch goals if stagnating
5. Preserve stepping stones for future exploration
6. Save all results to lineage

Monitor progress:

```bash
black adapt --full-status
black visualize --progress
black safety
```
