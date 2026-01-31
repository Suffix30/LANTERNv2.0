from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable


def load_knowledge(base_dir: Path | None = None) -> dict[str, Any]:
    base = base_dir or Path(__file__).parent / "knowledge"
    files = [
        "modules.json",
        "chains.json",
        "presets.json",
        "flags.json",
        "payloads.json",
        "config.json",
        "smart_mapping.json",
        "agent_brain.md",
        "operating_rules.md",
        "goal_loop.md",
        "tasks.json",
    ]
    knowledge: dict[str, Any] = {}
    for file_name in files:
        path = base / file_name
        if path.exists():
            if path.suffix == ".json":
                knowledge[file_name.replace(".json", "")] = json.loads(
                    path.read_text(encoding="utf-8")
                )
            else:
                knowledge[file_name.replace(path.suffix, "")] = path.read_text(
                    encoding="utf-8"
                )
    return knowledge


def load_brain(
    base_dir: Path | None = None,
    extra_doc_paths: Iterable[Path | str] | None = None,
) -> dict[str, Any]:
    brain = load_knowledge(base_dir)
    docs_base = Path(__file__).parent.parent / "docs"
    doc_files = [
        docs_base / "Agent-BLACK-Project-State.md",
        docs_base / "Agent-BLACK-Roadmap.md",
    ]
    if extra_doc_paths:
        for doc_path in extra_doc_paths:
            if doc_path:
                path = Path(doc_path)
                doc_files.append(path)

    seen = set()
    parsed_commands = None
    for doc_path in doc_files:
        if not doc_path.exists():
            continue
        key = doc_path.stem
        if key in seen:
            continue
        seen.add(key)
        content = doc_path.read_text(encoding="utf-8")
        brain[key] = content
        if doc_path.name == "Commands-Expanded.md":
            parsed_commands = parse_commands_reference(content)

    if parsed_commands:
        brain["commands_expanded_reference"] = parsed_commands
    return brain


def parse_commands_reference(text: str) -> dict[str, Any]:
    entries: list[dict[str, str | None]] = []
    best_practices: list[str] = []
    quick_lists: dict[str, list[str]] = {}
    pending_desc: str | None = None
    in_block = False
    command_lines: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```bash"):
            in_block = True
            command_lines = []
            continue
        if stripped == "```" and in_block:
            command = " ".join(l for l in (cmd.strip() for cmd in command_lines) if l)
            if command:
                entries.append({"description": pending_desc, "command": command})
            pending_desc = None
            in_block = False
            continue
        if in_block:
            command_lines.append(stripped)
            continue

        bold_match = re.match(r"\*\*(.+?)\*\*", stripped)
        if bold_match and ":" not in stripped:
            pending_desc = bold_match.group(1).strip()

        practice_match = re.match(r"^\d+\.\s+(.+)", stripped)
        if practice_match:
            best_practices.append(practice_match.group(1).strip())

        quick_match = re.match(r"\*\*(.+?)\*\*:\s*`([^`]+)`", stripped)
        if quick_match:
            name = quick_match.group(1).strip().lower()
            modules = [mod.strip() for mod in quick_match.group(2).split(",")]
            quick_lists[name] = modules

    return {
        "commands": entries,
        "best_practices": best_practices,
        "quick_module_lists": quick_lists,
    }