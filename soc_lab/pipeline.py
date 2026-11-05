"""Etapas del pipeline y sus rutas de datos."""

from __future__ import annotations

import json
from pathlib import Path

from soc_lab.parsers import parse_raw_dir
from soc_lab.schema import Alert, Event


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


def alerts_path(data_dir: Path) -> Path:
    return data_dir / "alerts.json"


def scenarios_path(data_dir: Path) -> Path:
    return raw_dir(data_dir) / "scenarios.json"


def detect(data_dir: Path) -> tuple[list[Alert], dict]:
    """Ejecuta todas las reglas, evalúa contra el ground truth y guarda alertas."""
    from soc_lab.detection.engine import load_rules, run_rules
    from soc_lab.detection.evaluate import evaluate

    rules = load_rules()
    alerts = run_rules(rules, load_events(data_dir))
    scenarios = json.loads(scenarios_path(data_dir).read_text(encoding="utf-8"))["scenarios"]
    metrics = evaluate(alerts, scenarios)
    payload = {
        "rules_loaded": len(rules),
        "metrics": metrics,
        "alerts": [a.to_dict() for a in alerts],
    }
    alerts_path(data_dir).write_text(json.dumps(payload, indent=1, ensure_ascii=False), encoding="utf-8")
    return alerts, metrics


def load_alerts(data_dir: Path) -> tuple[list[Alert], dict]:
    payload = json.loads(alerts_path(data_dir).read_text(encoding="utf-8"))
    return [Alert.from_dict(a) for a in payload["alerts"]], payload["metrics"]
