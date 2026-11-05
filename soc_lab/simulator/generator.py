"""Orquestador del simulador: ruido de fondo + escenarios de ataque.

Uso::

    python -m soc_lab generate --seed 1337 --out data

Produce ``data/raw/{sshd.log, windows.jsonl, firewall.log}`` y
``data/raw/scenarios.json`` (ground truth). La salida es determinista para una
semilla dada, de modo que alertas, casos y reportes son reproducibles.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path

from soc_lab.simulator.background import Background
from soc_lab.simulator.scenarios import ALL_SCENARIOS
from soc_lab.simulator.writer import RawLogs

DEFAULT_SEED = 1337
DEFAULT_DAY = datetime(2026, 10, 14, tzinfo=timezone.utc)


def generate(raw_dir: Path, seed: int = DEFAULT_SEED, day: datetime = DEFAULT_DAY) -> dict:
    rng = random.Random(seed)
    logs = RawLogs()
    Background(logs, rng, day).generate()
    scenarios = [build(logs, random.Random(f"{seed}-{build.__name__}"), day) for build in ALL_SCENARIOS]

    counts = logs.write(raw_dir)
    manifest = {
        "seed": seed,
        "day": day.date().isoformat(),
        "files": counts,
        "scenarios": [s.to_dict() for s in scenarios],
    }
    (raw_dir / "scenarios.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return manifest
