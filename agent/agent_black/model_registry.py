from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json


@dataclass(frozen=True)
class LocalModel:
    name: str
    engine: str
    path: Path


def _load_manifest(manifest_path: Path) -> LocalModel | None:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        name = str(data.get("name", manifest_path.parent.name)).strip()
        engine = str(data.get("engine", "llama.cpp")).strip()
        file_name = str(data.get("file", "")).strip()
        if not file_name:
            return None
        model_path = (manifest_path.parent / file_name).resolve()
        if not model_path.exists():
            return None
        return LocalModel(name=name, engine=engine, path=model_path)
    except Exception:
        return None


def discover_models(models_dir: Path) -> list[LocalModel]:
    models: list[LocalModel] = []
    if not models_dir.exists():
        return models

    for gguf in models_dir.glob("*.gguf"):
        models.append(LocalModel(name=gguf.stem, engine="llama.cpp", path=gguf))

    for manifest in models_dir.rglob("manifest.json"):
        model = _load_manifest(manifest)
        if model:
            models.append(model)

    return models


def select_model(models: list[LocalModel], requested: str | None) -> LocalModel | None:
    if not models:
        return None
    if not requested:
        return models[0]
    for model in models:
        if model.name == requested:
            return model
    return None

