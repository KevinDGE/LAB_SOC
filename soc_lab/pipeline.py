"""Etapas del pipeline y sus rutas de datos."""

from __future__ import annotations

import json
from pathlib import Path

from soc_lab.parsers import parse_raw_dir
from soc_lab.schema import Event


def raw_dir(data_dir: Path) -> Path:
    return data_dir / "raw"


def events_path(data_dir: Path) -> Path:
    return data_dir / "events.jsonl"


def normalize(data_dir: Path) -> list[Event]:
    """Parsea las fuentes crudas y escribe ``events.jsonl`` normalizado."""
    events = parse_raw_dir(raw_dir(data_dir))
    with events_path(data_dir).open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
    return events


def load_events(data_dir: Path) -> list[Event]:
    with events_path(data_dir).open(encoding="utf-8") as fh:
        return [Event.from_dict(json.loads(line)) for line in fh if line.strip()]
