from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

APP_DIR = Path.home() / '.vaultchat_desktop'
CONFIG_FILE = APP_DIR / 'client_config.json'


def ensure_app_dir() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> Dict[str, Any] | None:
    if not CONFIG_FILE.exists():
        return None
    return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))


def save_config(data: Dict[str, Any]) -> None:
    ensure_app_dir()
    CONFIG_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
