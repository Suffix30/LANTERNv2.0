#!/usr/bin/env python3
"""
Agent BLACK - Unified CLI Entry Point

Usage:
    black                    # Interactive chat (default)
    black chat               # Interactive chat
    black overwatch          # Situational awareness mode
    black overwatch --snapshot  # One-time analysis
    black autonomous <target> "<objective>"
    black pwn                # PWN/CTF utilities
    black --help
"""

import sys
import os
from pathlib import Path

agent_root = Path(__file__).parent
sys.path.insert(0, str(agent_root))

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
    else:
        print(f"[!] Unknown command: {command}")
        print_help()
        sys.exit(1)


def print_help():
    help_text = """
================================================================
                      AGENT BLACK CLI                           
================================================================

  COMMANDS:

    black                 Interactive chat (default)
    black chat            Interactive chat mode
    black overwatch       Situational awareness mode
    black autonomous      Autonomous pentesting
    black pwn             PWN/CTF utilities
    black obsidian        Obsidian vault integration
    black status          Check agent status

----------------------------------------------------------------
  OVERWATCH OPTIONS:

    black overwatch                  # Interactive Q&A mode
    black overwatch --snapshot       # One-time analysis
    black overwatch --watch          # Continuous monitoring (proactive alerts)
    black overwatch --watch --llm    # Watch mode with AI suggestions
    black overwatch --interval 5     # Custom check interval (seconds)

----------------------------------------------------------------
  AUTONOMOUS OPTIONS:

    black autonomous <target> "<objective>"
    black autonomous https://target.com "find SQLi"

----------------------------------------------------------------
  OBSIDIAN OPTIONS:

    black obsidian init <path>              # Initialize security vault
    black obsidian target <name> --platform HTB --ip 10.10.11.1
    black obsidian note "found sqli"        # Quick note
    black obsidian stats                    # Vault statistics

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
    if len(sys.argv) < 4:
        print("[!] Usage: black autonomous <target> \"<objective>\"")
        print("[!] Example: black autonomous https://target.com \"find SQL injection vulnerabilities\"")
        sys.exit(1)
    
    try:
        from scripts.black_autonomous import main as autonomous_main
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        autonomous_main()
    except ImportError as e:
        print(f"[!] Failed to load autonomous module: {e}")
        sys.exit(1)


def run_pwn():
    try:
        from scripts.black_pwn import main as pwn_main
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
