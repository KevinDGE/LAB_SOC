"""Parsers que normalizan cada fuente cruda al esquema ``Event``.

Para añadir una fuente nueva basta con escribir un módulo con una función
``parse_line(line) -> Event | None`` y registrarlo en ``PARSERS``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from soc_lab.parsers import firewall, sshd, windows
from soc_lab.schema import Event

# archivo crudo -> función de parseo
PARSERS: dict[str, Callable[[str], Event | None]] = {
    "sshd.log": sshd.parse_line,
    "windows.jsonl": windows.parse_line,
    "firewall.log": firewall.parse_line,
}


def parse_raw_dir(raw_dir: Path) -> list[Event]:
    """Lee todas las fuentes crudas de ``raw_dir`` y devuelve eventos ordenados."""
    events: list[Event] = []
    for filename, parser in PARSERS.items():
        path = raw_dir / filename
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                event = parser(line)
                if event is not None:
                    events.append(event)
    events.sort(key=lambda e: (e.timestamp, e.source, e.raw))
    return events
