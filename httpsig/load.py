"""Load message snapshots, keys, and policy. Inspect uses this; sign/verify should too."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class LoadError(ValueError):
    pass


def _read_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as e:
        raise LoadError(f"cannot read {path}: {e}") from e
    except json.JSONDecodeError as e:
        raise LoadError(f"cannot parse {path}: {e}") from e


def load_message(path: str | Path) -> dict[str, Any]:
    data = _read_json(path)
    if not isinstance(data, dict):
        raise LoadError("message must be a JSON object")
    for key in ("method", "scheme", "authority", "path", "headers", "now"):
        if key not in data:
            raise LoadError(f"message missing {key}")
    if not isinstance(data["headers"], list):
        raise LoadError("headers must be a list of [name, value]")
    if "query" not in data:
        data["query"] = ""
    if "body" not in data:
        data["body"] = ""
    data["_source"] = str(path)
    return data


def load_keys(path: str | Path) -> dict[str, Any]:
    data = _read_json(path)
    if not isinstance(data, dict) or "keys" not in data or not isinstance(data["keys"], dict):
        raise LoadError("keys file must contain a keys object")
    return data


def load_policy(path: str | Path) -> dict[str, Any]:
    data = _read_json(path)
    if not isinstance(data, dict):
        raise LoadError("policy must be a JSON object")
    return data


def signature_labels(message: dict[str, Any]) -> list[str]:
    names = []
    for name, value in message.get("headers") or []:
        if isinstance(name, str) and name.lower() == "signature-input":
            # labels are the sf-dictionary keys; a full parse belongs in sign/verify
            names.append(value)
    return names
