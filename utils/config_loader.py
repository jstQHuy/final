"""Project-wide YAML config loader.

Goals:
1) Provide a single place to load configs/config.yaml safely.
2) Normalize common typos in section names (e.g., 'excution' -> 'execution').
3) Optionally expand ${ENV_VAR} placeholders from the environment.

This module is intentionally lightweight and has no LangChain/OpenAI deps.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional

import yaml


_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env_vars(value: Any) -> Any:
    """Recursively expand ${VAR} placeholders in strings."""
    if isinstance(value, str):
        def _sub(m: re.Match[str]) -> str:
            return os.environ.get(m.group(1), "")

        return _ENV_PATTERN.sub(_sub, value)
    if isinstance(value, list):
        return [_expand_env_vars(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    return value


def normalize_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize common naming issues without being destructive."""
    runtime = cfg.get("runtime")
    if isinstance(runtime, dict):
        # Common typos seen in the repo/user configs
        aliases = {
            "excution": "execution",
            "exeuction": "execution",
            "planing": "planning",
        }
        for bad, good in aliases.items():
            if bad in runtime and good not in runtime:
                runtime[good] = runtime[bad]
        cfg["runtime"] = runtime
    return cfg


def load_config(
    config_path: str,
    *,
    expand_env: bool = True,
) -> Dict[str, Any]:
    """Load YAML config; optionally expand env vars; normalize known typos."""
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    if expand_env:
        cfg = _expand_env_vars(cfg)
    cfg = normalize_config(cfg)
    return cfg


def get_runtime_section(cfg: Dict[str, Any], name: str) -> Dict[str, Any]:
    """Safely fetch cfg['runtime'][name] with normalization applied."""
    cfg = normalize_config(cfg)
    runtime = cfg.get("runtime")
    if not isinstance(runtime, dict):
        return {}
    sec = runtime.get(name)
    return sec if isinstance(sec, dict) else {}
