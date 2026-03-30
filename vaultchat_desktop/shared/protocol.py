from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

APP_NAME = 'VaultChat Desktop'
BOOTSTRAP_ADMIN_PASSWORD = 'admin'


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode('ascii'))


def random_code(length_bytes: int = 24) -> str:
    return b64e(os.urandom(length_bytes)).rstrip('=')


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
