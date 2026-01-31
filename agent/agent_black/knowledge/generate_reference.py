from __future__ import annotations

import json
from pathlib import Path
from typing import Any


BASE = Path(__file__).parent
OUT = BASE / "lantern_full_reference.md"


def _load(name: str) -> dict[str, Any]:
    return json.loads((BASE / name).read_text(encoding="utf-8"))


def _md_list(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def main() -> int:
    modules = _load("modules.json")
    chains = _load("chains.json")
    presets = _load("presets.json")
    flags = _load("flags.json")
    payloads = _load("payloads.json")
    config = _load("config.json")
    smart = _load("smart_mapping.json")

    lines: list[str] = []
    lines.append("# LANTERN Full Reference")
    lines.append("")
    lines.append("This document is generated from the live LANTERN codebase and")
    lines.append("reflects all modules, presets, flags, chains, payload sources,")
    lines.append("and configuration defaults.")
    lines.append("")

    lines.append("## Modules")
    lines.append(f"Total modules: {len(modules.get('modules', []))}")
    lines.append("")
    lines.append("### Module Lists")
    lines.append("**ALL_MODULES**")
    lines.append(_md_list(modules.get("all", [])))
    lines.append("")
    lines.append("**FAST_MODULES**")
    lines.append(_md_list(modules.get("fast", [])))
    lines.append("")
    lines.append("**DEEP_MODULES**")
    lines.append(_md_list(modules.get("deep", [])))
    lines.append("")

    lines.append("### Module Details")
    for mod in modules.get("modules", []):
        lines.append(f"#### `{mod['name']}`")
        lines.append(f"- Description: {mod.get('description') or 'n/a'}")
        lines.append(f"- Category: {mod.get('category') or 'n/a'}")
        lines.append(f"- Exploitable: {mod.get('exploitable')}")
        lines.append(f"- File: `{mod.get('file')}`")
        lines.append("")

    lines.append("## Attack Chains")
    for chain, mods in chains.get("chains", {}).items():
        lines.append(f"### `{chain}`")
        lines.append(_md_list(mods))
        lines.append("")

    lines.append("## Presets")
    for preset in presets.get("presets", []):
        lines.append(f"### `{preset.get('name')}`")
        lines.append(f"- Description: {preset.get('description') or 'n/a'}")
        lines.append(f"- File: `{preset.get('file')}`")
        lines.append("- Modules:")
        lines.append(_md_list(preset.get("modules", [])))
        lines.append("- Config:")
        for key, value in preset.get("config", {}).items():
            lines.append(f"  - `{key}`: {value}")
        lines.append("")

    lines.append("## CLI Flags")
    for spec in flags.get("flags", []):
        flag_str = ", ".join(spec.get("flags", []))
        lines.append(f"### {flag_str}")
        if spec.get("help"):
            lines.append(f"- Help: {spec['help']}")
        if spec.get("default") is not None:
            lines.append(f"- Default: {spec['default']}")
        if spec.get("choices"):
            lines.append(f"- Choices: {spec['choices']}")
        if spec.get("type"):
            lines.append(f"- Type: {spec['type']}")
        if spec.get("action"):
            lines.append(f"- Action: {spec['action']}")
        lines.append("")

    lines.append("## Config Defaults")
    defaults = config.get("config_defaults", {})
    for key, value in defaults.items():
        lines.append(f"- `{key}`: {value}")
    lines.append("")

    lines.append("## Smart Module Mapping")
    mapping = smart.get("module_mapping", {})
    for key, value in mapping.items():
        lines.append(f"- `{key}` → `{value}`")
    lines.append("")

    lines.append("## Payload Sources")
    for entry in payloads.get("payloads", []):
        lines.append(f"- `{entry['file']}` ({entry['size']} bytes)")
    lines.append("")

    OUT.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

