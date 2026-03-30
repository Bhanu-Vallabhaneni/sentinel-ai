from __future__ import annotations

import json
from pathlib import Path

from app.models import SecurityEvent


def load_sample_events() -> list[SecurityEvent]:
    path = Path(__file__).resolve().parent.parent / "data" / "sample_auth_logs.json"
    raw_events = json.loads(path.read_text(encoding="utf-8"))
    return [SecurityEvent(**item) for item in raw_events]
