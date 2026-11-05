"""Esquema normalizado del laboratorio (inspirado en Elastic Common Schema).

Todas las fuentes (sshd, Windows Security/System, firewall) se normalizan a
``Event``. Las reglas de detección operan exclusivamente sobre este esquema,
de modo que añadir una fuente nueva solo requiere escribir un parser.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_ts(value: str) -> datetime:
    """Convierte un timestamp ISO-8601 UTC (``...Z``) en ``datetime`` aware."""
    return datetime.strptime(value, TS_FORMAT).replace(tzinfo=timezone.utc)


def format_ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime(TS_FORMAT)


@dataclass
class Event:
    timestamp: datetime
    source: str  # sshd | windows | firewall
    event_code: str  # p.ej. 4625, 7045, sshd_failed, fw_conn
    category: str  # authentication | network | service
    action: str  # logon_failure | logon_success | connection | service_install
    outcome: str  # success | failure | allowed | denied
    host: str | None = None  # equipo que registra el evento
    user: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    logon_type: int | None = None
    service_name: str | None = None
    raw: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, name: str) -> Any:
        """Acceso a campos por nombre; ``extra.x`` accede al diccionario extra."""
        if name.startswith("extra."):
            return self.extra.get(name[len("extra."):])
        return getattr(self, name, None)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = format_ts(self.timestamp)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        data = dict(data)
        data["timestamp"] = parse_ts(data["timestamp"])
        return cls(**data)


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    tactic: list[str]
    techniques: list[dict[str, str]]
    first_seen: datetime
    last_seen: datetime
    group: dict[str, Any]
    entities: dict[str, list[str]]
    event_count: int
    summary: str
    evidence: list[Event] = field(default_factory=list)

    def to_dict(self, include_evidence: bool = True) -> dict[str, Any]:
        data = {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "tactic": self.tactic,
            "techniques": self.techniques,
            "first_seen": format_ts(self.first_seen),
            "last_seen": format_ts(self.last_seen),
            "group": self.group,
            "entities": self.entities,
            "event_count": self.event_count,
            "summary": self.summary,
        }
        if include_evidence:
            data["evidence"] = [e.to_dict() for e in self.evidence]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        data = dict(data)
        data["first_seen"] = parse_ts(data["first_seen"])
        data["last_seen"] = parse_ts(data["last_seen"])
        data["evidence"] = [Event.from_dict(e) for e in data.get("evidence", [])]
        return cls(**data)


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
