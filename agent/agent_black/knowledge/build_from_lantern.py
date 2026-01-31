from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


LANTERN_ROOT = Path(r".")
OUTPUT_DIR = Path(__file__).parent


@dataclass
class ArgSpec:
    flags: list[str]
    dest: str | None
    help: str | None
    default: Any
    action: str | None
    choices: list[Any] | None
    arg_type: str | None


def _literal(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _extract_argparse_specs(cli_path: Path) -> list[ArgSpec]:
    tree = ast.parse(cli_path.read_text(encoding="utf-8"))
    specs: list[ArgSpec] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr != "add_argument":
                continue
            if not node.args:
                continue
            flags = []
            for arg in node.args:
                val = _literal(arg)
                if isinstance(val, str):
                    flags.append(val)
            kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            dest = _literal(kwargs.get("dest")) if "dest" in kwargs else None
            help_text = _literal(kwargs.get("help")) if "help" in kwargs else None
            default = _literal(kwargs.get("default")) if "default" in kwargs else None
            action = _literal(kwargs.get("action")) if "action" in kwargs else None
            choices = _literal(kwargs.get("choices")) if "choices" in kwargs else None
            arg_type = None
            if "type" in kwargs:
                type_node = kwargs["type"]
                if isinstance(type_node, ast.Name):
                    arg_type = type_node.id
                else:
                    arg_type = str(_literal(type_node)) if _literal(type_node) else None
            specs.append(
                ArgSpec(
                    flags=flags,
                    dest=dest,
                    help=help_text,
                    default=default,
                    action=action,
                    choices=choices,
                    arg_type=arg_type,
                )
            )
    return specs


def _extract_cli_lists(cli_path: Path) -> dict[str, Any]:
    tree = ast.parse(cli_path.read_text(encoding="utf-8"))
    values: dict[str, Any] = {}
    targets = {"ALL_MODULES", "FAST_MODULES", "DEEP_MODULES", "CHAIN_MODULES"}

    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in targets:
                    values[target.id] = _literal(node.value)
    return values


def _extract_config_defaults(cli_path: Path) -> dict[str, Any]:
    tree = ast.parse(cli_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id == "config":
                    cfg = _literal(node.value)
                    if isinstance(cfg, dict):
                        return cfg
    return {}


def _extract_smart_mapping(cli_path: Path) -> dict[str, Any]:
    tree = ast.parse(cli_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id == "module_mapping":
                    mapping = _literal(node.value)
                    if isinstance(mapping, dict):
                        return mapping
    return {}


def _extract_show_modules_info(cli_path: Path) -> dict[str, dict[str, str]]:
    text = cli_path.read_text(encoding="utf-8")
    marker = "modules_info = {"
    if marker not in text:
        return {}
    start = text.index(marker) + len(marker)
    end = text.index("}", start)
    snippet = "{" + text[start:end] + "}"
    try:
        return ast.literal_eval(snippet)
    except Exception:
        return {}


def _extract_module_metadata(mod_path: Path) -> dict[str, Any]:
    tree = ast.parse(mod_path.read_text(encoding="utf-8"))
    meta = {"file": str(mod_path)}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    if isinstance(stmt.targets[0], ast.Name):
                        name = stmt.targets[0].id
                        if name in {"name", "description", "exploitable"}:
                            meta[name] = _literal(stmt.value)
    return meta


def build_modules(modules_dir: Path, cli_info: dict[str, Any], type_info: dict[str, Any]) -> dict[str, Any]:
    modules = []
    for mod_file in sorted(modules_dir.glob("*.py")):
        if mod_file.name.startswith("__"):
            continue
        meta = _extract_module_metadata(mod_file)
        if "name" not in meta:
            continue
        name = meta["name"]
        desc, category = type_info.get(name, (None, None))
        modules.append(
            {
                "name": name,
                "description": meta.get("description") or desc,
                "category": category,
                "exploitable": bool(meta.get("exploitable", False)),
                "file": meta["file"],
            }
        )

    return {
        "all": cli_info.get("ALL_MODULES", []),
        "fast": cli_info.get("FAST_MODULES", []),
        "deep": cli_info.get("DEEP_MODULES", []),
        "modules": sorted(modules, key=lambda m: m["name"]),
    }


def build_chains(cli_info: dict[str, Any]) -> dict[str, Any]:
    return {"chains": cli_info.get("CHAIN_MODULES", {})}


def build_presets(presets_dir: Path) -> dict[str, Any]:
    presets = []
    for preset_file in sorted(presets_dir.glob("*.yml")):
        data = yaml.safe_load(preset_file.read_text(encoding="utf-8"))
        data["file"] = str(preset_file)
        presets.append(data)
    return {"presets": presets}


def build_flags(cli_path: Path) -> dict[str, Any]:
    specs = _extract_argparse_specs(cli_path)
    out = []
    for spec in specs:
        out.append(
            {
                "flags": spec.flags,
                "dest": spec.dest,
                "help": spec.help,
                "default": spec.default,
                "action": spec.action,
                "choices": spec.choices,
                "type": spec.arg_type,
            }
        )
    return {"flags": out}


def build_payloads(payloads_dir: Path) -> dict[str, Any]:
    payloads = []
    for file_path in sorted(payloads_dir.rglob("*")):
        if file_path.is_file():
            payloads.append(
                {
                    "file": str(file_path),
                    "size": file_path.stat().st_size,
                }
            )
    return {"payloads": payloads}


def build_full_reference(
    modules: dict[str, Any],
    chains: dict[str, Any],
    presets: dict[str, Any],
    flags: dict[str, Any],
    payloads: dict[str, Any],
    config: dict[str, Any],
    smart: dict[str, Any],
) -> str:
    lines = [
        "# LANTERN Full Reference",
        "",
        "This document is auto-generated from the live LANTERN codebase.",
        "Run `python build_from_lantern.py` from the LANTERN root to regenerate.",
        "",
        "## Modules",
        f"Total modules: {len(modules.get('modules', []))}",
        "",
        "### Module Lists",
        "**ALL_MODULES**",
    ]
    for m in modules.get("all", []):
        lines.append(f"- {m}")
    lines.append("")
    lines.append("**FAST_MODULES** (used with --fast)")
    for m in modules.get("fast", []):
        lines.append(f"- {m}")
    lines.append("")
    lines.append("**DEEP_MODULES** (used with --deep)")
    for m in modules.get("deep", []):
        lines.append(f"- {m}")
    lines.append("")
    lines.append("### Module Details")
    lines.append("| Module | Description | Category | Exploitable |")
    lines.append("|--------|-------------|----------|-------------|")
    for m in modules.get("modules", []):
        exp = "Yes" if m.get("exploitable") else "No"
        lines.append(f"| {m['name']} | {m.get('description', '')} | {m.get('category', '')} | {exp} |")
    lines.append("")
    lines.append("## Attack Chains")
    lines.append("Pre-configured module combinations for specific attack goals.")
    lines.append("")
    for chain_name, chain_mods in chains.get("chains", {}).items():
        lines.append(f"**{chain_name}**: {', '.join(chain_mods)}")
    lines.append("")
    lines.append("## Presets")
    for preset in presets.get("presets", []):
        lines.append(f"### {preset.get('name', 'Unknown')}")
        if preset.get("description"):
            lines.append(f"{preset['description']}")
        if preset.get("modules"):
            lines.append(f"- Modules: {', '.join(preset['modules'])}")
        if preset.get("options"):
            lines.append(f"- Options: {preset['options']}")
        lines.append("")
    lines.append("## CLI Flags")
    lines.append("| Flag | Description | Default |")
    lines.append("|------|-------------|---------|")
    for f in flags.get("flags", []):
        flag_str = ", ".join(f.get("flags", []))
        help_text = (f.get("help") or "").replace("|", "\\|")[:60]
        default = f.get("default")
        default_str = str(default) if default is not None else ""
        lines.append(f"| `{flag_str}` | {help_text} | {default_str} |")
    lines.append("")
    lines.append("## Payloads")
    lines.append(f"Total payload files: {len(payloads.get('payloads', []))}")
    lines.append("")
    for p in payloads.get("payloads", []):
        lines.append(f"- {p['file']} ({p['size']} bytes)")
    lines.append("")
    lines.append("## Smart Module Mapping")
    lines.append("Technology to module mapping for --smart mode:")
    lines.append("")
    for tech, mods in smart.get("module_mapping", {}).items():
        lines.append(f"- **{tech}**: {', '.join(mods)}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    cli_path = LANTERN_ROOT / "core" / "cli.py"
    modules_dir = LANTERN_ROOT / "modules"
    presets_dir = LANTERN_ROOT / "presets"
    payloads_dir = LANTERN_ROOT / "payloads"

    cli_info = _extract_cli_lists(cli_path)
    type_info = _extract_show_modules_info(cli_path)
    config_defaults = _extract_config_defaults(cli_path)
    smart_mapping = _extract_smart_mapping(cli_path)

    modules = build_modules(modules_dir, cli_info, type_info)
    chains = build_chains(cli_info)
    presets = build_presets(presets_dir)
    flags = build_flags(cli_path)
    payloads = build_payloads(payloads_dir)
    config = {"config_defaults": config_defaults}
    smart = {"module_mapping": smart_mapping}

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    (OUTPUT_DIR / "modules.json").write_text(json.dumps(modules, indent=2), encoding="utf-8")
    (OUTPUT_DIR / "chains.json").write_text(json.dumps(chains, indent=2), encoding="utf-8")
    (OUTPUT_DIR / "presets.json").write_text(json.dumps(presets, indent=2), encoding="utf-8")
    (OUTPUT_DIR / "flags.json").write_text(json.dumps(flags, indent=2), encoding="utf-8")
    (OUTPUT_DIR / "payloads.json").write_text(json.dumps(payloads, indent=2), encoding="utf-8")
    (OUTPUT_DIR / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    (OUTPUT_DIR / "smart_mapping.json").write_text(json.dumps(smart, indent=2), encoding="utf-8")

    full_ref = build_full_reference(modules, chains, presets, flags, payloads, config, smart)
    (OUTPUT_DIR / "lantern_full_reference.md").write_text(full_ref, encoding="utf-8")

    print(f"Generated knowledge files in {OUTPUT_DIR}")
    print(f"  - {len(modules.get('modules', []))} modules")
    print(f"  - {len(chains.get('chains', {}))} chains")
    print(f"  - {len(presets.get('presets', []))} presets")
    print(f"  - {len(flags.get('flags', []))} CLI flags")
    print(f"  - {len(payloads.get('payloads', []))} payload files")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

