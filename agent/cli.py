#!/usr/bin/env python3
import sys
import os
from pathlib import Path
  
agent_root = Path(__file__).parent
project_root = agent_root.parent
sys.path.insert(0, str(agent_root))
sys.path.insert(0, str(project_root))

os.environ.setdefault("BLACK_AGENT_ROOT", str(agent_root))

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help"]:
        print_help()
        return
    
    command = sys.argv[1].lower()
    
    if command == "chat" or (len(sys.argv) == 1):
        run_chat()
    elif command == "overwatch":
        run_overwatch()
    elif command == "autonomous":
        run_autonomous()
    elif command == "pwn":
        run_pwn()
    elif command == "status":
        run_status()
    elif command == "obsidian":
        run_obsidian()
    elif command == "adapt":
        run_adapt()
    elif command == "lineage":
        run_lineage()
    elif command == "benchmark":
        run_benchmark()
    elif command == "visualize":
        run_visualize()
    elif command == "capabilities":
        run_capabilities()
    elif command == "safety":
        run_safety()
    elif command == "goals":
        run_goals()
    elif command == "transfer":
        run_transfer()
    else:
        print(f"[!] Unknown command: {command}")
        print_help()
        sys.exit(1)


def print_help():
    help_text = """
================================================================
                      AGENT BLACK CLI                           
              Self-Improving AI Security Assistant
================================================================

  COMMANDS:

    black                 Interactive chat (default)
    black chat            Interactive chat mode
    black overwatch       Situational awareness mode
    black autonomous      Autonomous pentesting
    black adapt           Adaptive improvement cycle
    black lineage         Show improvement lineage
    black benchmark       Run detection benchmark
    black visualize       Generate visualizations
    black capabilities    List all capabilities
    black safety          Check safety validations
    black goals           Manage improvement goals
    black transfer        Test improvement transfer
    black pwn             PWN/CTF utilities
    black obsidian        Obsidian vault integration
    black status          Check agent status

----------------------------------------------------------------
  ADAPTIVE ENGINE:

    black adapt <target>              # Run improvement cycle
    black adapt <target> --continuous 5  # Run 5 generations
    black adapt <target> --branch 3   # Explore 3 parallel branches
    black adapt --status              # Show full engine status
    black adapt --full-status         # Include safety & transfer info

----------------------------------------------------------------
  GOAL MANAGEMENT:

    black goals                       # Show active goal
    black goals --switch accuracy     # Switch to accuracy goal
    black goals --switch coverage     # Switch to coverage goal
    black goals --switch precision    # Switch to precision goal
    black goals --history             # Show goal switch history

----------------------------------------------------------------
  SAFETY & VALIDATION:

    black safety                      # Show safety summary
    black safety --check <file>       # Check improvement safety
    black safety --flagged            # Show flagged improvements

----------------------------------------------------------------
  TRANSFER TESTING:

    black transfer --module sqli      # Test cross-module transfer
    black transfer --target <url>     # Test cross-target transfer

----------------------------------------------------------------
  LINEAGE & VISUALIZATION:

    black lineage                     # Show improvement tree
    black lineage --summary           # Lineage summary
    black lineage --stones            # Show stepping stones
    black visualize --tree            # ASCII tree
    black visualize --html            # Generate HTML visualization
    black visualize --progress        # Progress chart

----------------------------------------------------------------
  BENCHMARK:

    black benchmark                   # Run full benchmark
    black benchmark --tags injection  # Filter by tags
    black benchmark --compare file1 file2  # Compare results

----------------------------------------------------------------
  OVERWATCH OPTIONS:

    black overwatch                  # Interactive Q&A mode
    black overwatch --snapshot       # One-time analysis
    black overwatch --watch          # Continuous monitoring
    black overwatch --interval 5     # Custom check interval

----------------------------------------------------------------
  AUTONOMOUS OPTIONS:

    black autonomous <target> "<objective>"
    black autonomous https://target.com "find SQLi"

================================================================
"""
    print(help_text)


def run_chat():
    try:
        from scripts.black import main as chat_main
        chat_main()
    except ImportError as e:
        print(f"[!] Failed to load chat module: {e}")
        print("[*] Make sure dependencies are installed: pip install -r requirements.txt")
        sys.exit(1)


def run_overwatch():
    try:
        from scripts.black_overwatch import main as overwatch_main
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        overwatch_main()
    except ImportError as e:
        print(f"[!] Failed to load overwatch module: {e}")
        sys.exit(1)


def run_autonomous():
    if len(sys.argv) < 3:
        print("[!] Usage: black autonomous <target> [objective]")
        print("[!] Example: black autonomous https://target.com \"find SQL injection\"")
        sys.exit(1)
    
    try:
        import asyncio
        from scripts.black_autonomous import main as autonomous_main
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        asyncio.run(autonomous_main())
    except ImportError as e:
        print(f"[!] Failed to load autonomous module: {e}")
        sys.exit(1)


def run_pwn():
    try:
        from scripts.black_pwn import main as pwn_main
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        pwn_main()
    except ImportError as e:
        print(f"[!] Failed to load PWN module: {e}")
        sys.exit(1)


def run_obsidian():
    try:
        from integration.obsidian import main as obsidian_main
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        obsidian_main()
    except ImportError as e:
        print(f"[!] Failed to load Obsidian module: {e}")
        sys.exit(1)


def run_status():
    print("\n[*] Agent BLACK Status Check")
    print("=" * 40)
    
    models_dir = agent_root / "agent_black" / "models"
    gguf_files = list(models_dir.glob("*.gguf")) if models_dir.exists() else []
    
    if gguf_files:
        print(f"[+] Local Model: {gguf_files[0].name}")
        size_gb = gguf_files[0].stat().st_size / (1024**3)
        print(f"    Size: {size_gb:.1f} GB")
        try:
            from llama_cpp import Llama
            print("[+] llama-cpp-python: Installed")
        except ImportError:
            print("[-] llama-cpp-python: NOT installed (run: pip install llama-cpp-python)")
    else:
        print("[-] Local Model: None found in agent/agent_black/models/")
        try:
            import ollama
            models = ollama.list()
            print("[+] Ollama: Connected")
            model_names = [m.get('name', m.get('model', 'unknown')) for m in models.get('models', [])]
            if model_names:
                print(f"    Models: {', '.join(model_names[:5])}")
        except Exception as e:
            print(f"[-] Ollama: Not running ({e})")
    
    knowledge_dir = agent_root / "agent_black" / "knowledge"
    if knowledge_dir.exists():
        md_files = list(knowledge_dir.glob("*.md"))
        json_files = list(knowledge_dir.glob("*.json"))
        print(f"[+] Knowledge: {len(md_files)} docs, {len(json_files)} data files")
    else:
        print("[-] Knowledge: Directory not found")
    
    lantern_docs = knowledge_dir / "lantern_docs" if knowledge_dir.exists() else None
    if lantern_docs and lantern_docs.exists():
        doc_count = len(list(lantern_docs.rglob("*.*")))
        print(f"[+] LANTERN Docs: {doc_count} files integrated")
    
    payloads_dir = agent_root.parent / "payloads"
    if payloads_dir.exists():
        payload_files = list(payloads_dir.glob("*.txt"))
        print(f"[+] Payloads: {len(payload_files)} payload files available")
    
    print("=" * 40)


def run_adapt():
    if "--status" in sys.argv:
        try:
            from agent_black.adaptive_engine import print_engine_status
            print(print_engine_status())
        except ImportError as e:
            print(f"[!] Failed to load adaptive engine: {e}")
        return
    if "--full-status" in sys.argv:
        try:
            from agent_black.adaptive_engine import AdaptiveEngine
            import json
            engine = AdaptiveEngine()
            status = engine.get_full_status()
            print("\n" + "=" * 70)
            print("FULL ADAPTIVE ENGINE STATUS")
            print("=" * 70)
            print(json.dumps(status, indent=2, default=str))
            print("=" * 70)
        except ImportError as e:
            print(f"[!] Failed to load adaptive engine: {e}")
        return
    
    if len(sys.argv) < 3:
        print("[!] Usage: black adapt <target> [--continuous N] [--branch N]")
        print("[!] Or: black adapt --status | --full-status")
        sys.exit(1)
    
    target = sys.argv[2]
    if target.startswith("--"):
        print(f"[!] Invalid target: {target}")
        print("[!] Usage: black adapt <target> [--continuous N] [--branch N]")
        sys.exit(1)
    continuous = None
    branch_count = None
    
    if "--continuous" in sys.argv:
        idx = sys.argv.index("--continuous")
        if idx + 1 < len(sys.argv):
            continuous = int(sys.argv[idx + 1])
    
    if "--branch" in sys.argv:
        idx = sys.argv.index("--branch")
        if idx + 1 < len(sys.argv):
            branch_count = int(sys.argv[idx + 1])
    
    try:
        from agent_black.adaptive_engine import AdaptiveEngine
        engine = AdaptiveEngine()
        
        if branch_count:
            print(f"\n[*] Running branching exploration with {branch_count} branches...")
            result = engine.run_branching_exploration(target, num_branches=branch_count)
            print(f"\nBest branch: {result['best_branch']}")
            print(f"Best score: {result['best_score']:.3f}")
            print(f"Total branches explored: {len(result['branches'])}")
        elif continuous:
            result = engine.run_continuous([target], generations=continuous)
            print(f"\nFinal accuracy: {result['final_accuracy']:.3f}")
        else:
            result = engine.run_cycle(target)
            print(f"\nImprovements applied: {result['improvements_applied']}")
    except ImportError as e:
        print(f"[!] Failed to load adaptive engine: {e}")
        sys.exit(1)


def run_lineage():
    try:
        from agent_black.learning import get_lineage_summary, ImprovementLineage, SteppingStoneTracker
        
        if "--stones" in sys.argv:
            lineage = ImprovementLineage()
            tracker = SteppingStoneTracker(lineage)
            
            breakthroughs = tracker.identify_breakthrough_ancestors()
            candidates = tracker.get_exploration_candidates()
            
            print("\n" + "=" * 60)
            print("STEPPING STONES")
            print("=" * 60)
            print(f"\nBreakthrough Ancestors: {len(breakthroughs)}")
            for node_id in breakthroughs:
                node = lineage.get_node(node_id)
                score = node.get("accuracy_score", 0) if node else 0
                print(f"  - {node_id} (score: {score:.3f})")
            
            print(f"\nExploration Candidates: {len(candidates)}")
            for node_id in candidates[:10]:
                node = lineage.get_node(node_id)
                children = node.get("children_count", 0) if node else 0
                print(f"  - {node_id} (children: {children})")
            
            print("=" * 60)
        else:
            print(get_lineage_summary())
    except ImportError as e:
        print(f"[!] Failed to load learning module: {e}")
        sys.exit(1)


def run_benchmark():
    if "--compare" in sys.argv:
        idx = sys.argv.index("--compare")
        if idx + 2 < len(sys.argv):
            try:
                from lab.benchmark import compare_benchmarks
                comparison = compare_benchmarks(Path(sys.argv[idx + 1]), Path(sys.argv[idx + 2]))
                print(f"Accuracy change: {comparison['accuracy_delta']*100:+.1f}%")
                print(f"Improved: {comparison['improved']}")
            except ImportError as e:
                print(f"[!] Failed to load benchmark: {e}")
        return
    
    tags = None
    if "--tags" in sys.argv:
        idx = sys.argv.index("--tags")
        if idx + 1 < len(sys.argv):
            tags = sys.argv[idx + 1].split(",")
    
    try:
        from lab.benchmark import run_benchmark, print_benchmark_report
        report = run_benchmark(tags=tags)
        print(print_benchmark_report(report))
    except ImportError as e:
        print(f"[!] Failed to load benchmark: {e}")
        sys.exit(1)


def run_visualize():
    try:
        from agent_black.visualize import LineageVisualizer, VISUALIZATION_DIR
        visualizer = LineageVisualizer()
        
        if "--html" in sys.argv:
            html_file = VISUALIZATION_DIR / "lineage.html"
            visualizer.generate_html_tree(html_file)
            print(f"Generated: {html_file}")
        elif "--progress" in sys.argv:
            print(visualizer.generate_progress_chart())
        else:
            print(visualizer.generate_ascii_tree())
    except ImportError as e:
        print(f"[!] Failed to load visualizer: {e}")
        sys.exit(1)


def run_capabilities():
    try:
        from agents.agent_black import AgentBlack
        agent = AgentBlack(load_model=False)
        
        print("\n" + "=" * 60)
        print("AGENT BLACK CAPABILITIES")
        print("=" * 60)
        
        if agent.capability_registry:
            print(agent.capability_registry.to_prompt_format())
        else:
            print("Capability registry not initialized")
        
        print("=" * 60)
    except ImportError as e:
        print(f"[!] Failed to load agent: {e}")
        sys.exit(1)


def run_safety():
    try:
        from agent_black.learning import SafetyValidator
        validator = SafetyValidator()
        
        if "--flagged" in sys.argv:
            flagged = validator._validations.get("flagged_improvements", [])
            print(f"\nFlagged Improvements: {len(flagged)}")
            for imp_id in flagged:
                print(f"  - {imp_id}")
        else:
            summary = validator.get_safety_summary()
            print("\n" + "=" * 60)
            print("SAFETY VALIDATION SUMMARY")
            print("=" * 60)
            print(f"\nTotal Checks: {summary['total_checks']}")
            print(f"Hallucinations Detected: {summary['hallucinations_detected']}")
            print(f"Reward Hacks Detected: {summary['reward_hacks_detected']}")
            print(f"Flagged Improvements: {summary['flagged_improvements']}")
            print("=" * 60)
    except ImportError as e:
        print(f"[!] Failed to load safety validator: {e}")
        sys.exit(1)


def run_goals():
    try:
        from agent_black.learning import GoalManager
        manager = GoalManager()
        
        if "--switch" in sys.argv:
            idx = sys.argv.index("--switch")
            if idx + 1 < len(sys.argv):
                new_goal = sys.argv[idx + 1]
                if manager.switch_goal(new_goal, "Manual switch via CLI"):
                    print(f"[+] Switched to goal: {new_goal}")
                else:
                    print(f"[!] Invalid goal: {new_goal}")
                    print(f"    Available: {', '.join(manager.GOALS.keys())}")
        elif "--history" in sys.argv:
            history = manager._goals.get("goal_history", [])
            print("\nGoal Switch History:")
            for entry in history[-10:]:
                print(f"  {entry['from']} -> {entry['to']} ({entry['timestamp'][:10]})")
                if entry.get("reason"):
                    print(f"    Reason: {entry['reason']}")
        else:
            current = manager.get_active_goal()
            weight = manager.get_goal_weight()
            print(f"\nActive Goal: {current}")
            print(f"Weight: {weight}")
            print(f"Description: {manager.GOALS[current]['description']}")
            print(f"\nAvailable Goals:")
            for goal, info in manager.GOALS.items():
                marker = " <--" if goal == current else ""
                print(f"  {goal}: {info['description']}{marker}")
    except ImportError as e:
        print(f"[!] Failed to load goal manager: {e}")
        sys.exit(1)


def run_transfer():
    try:
        from agent_black.improvement_applier import TransferTester
        tester = TransferTester()
        
        if "--module" in sys.argv:
            idx = sys.argv.index("--module")
            if idx + 1 < len(sys.argv):
                module = sys.argv[idx + 1]
                print(f"\n[*] Testing transfer from {module} module...")
                summary = tester.get_transfer_summary()
                print(f"Total Transfer Tests: {summary['total_tests']}")
                print(f"Average Success Rate: {summary['avg_success_rate']*100:.1f}%")
        else:
            summary = tester.get_transfer_summary()
            print("\n" + "=" * 60)
            print("TRANSFER TESTING SUMMARY")
            print("=" * 60)
            print(f"\nTotal Tests: {summary['total_tests']}")
            print(f"Average Success Rate: {summary['avg_success_rate']*100:.1f}%")
            print("=" * 60)
    except ImportError as e:
        print(f"[!] Failed to load transfer tester: {e}")
        sys.exit(1)


def run_default():
    if len(sys.argv) == 1:
        run_chat()
    else:
        main()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        run_chat()
    else:
        main()
