"""Motor de detección declarativo (detection-as-code).

Las reglas viven en ``soc_lab/detection/rules/*.yml`` y se evalúan sobre
eventos normalizados (``soc_lab.schema.Event``). Tipos de lógica soportados:

``threshold``
    Cuenta eventos por grupo dentro de una ventana deslizante.
``distinct``
    Cuenta valores distintos de ``distinct_field`` por grupo dentro de la
    ventana (p. ej. usuarios distintos → password spraying).
``sequence``
    Dos pasos ordenados por grupo: al menos ``min_count`` eventos del primer
    paso seguidos de un evento del segundo dentro de la ventana
    (p. ej. fallos → éxito).

Cuando una ventana cumple la condición, la alerta absorbe los eventos
siguientes del mismo grupo mientras no haya un hueco mayor que la ventana;
así un ataque largo produce una sola alerta en vez de cientos.

Filtros: ``campo: valor`` (igualdad), ``campo: [a, b]`` (pertenencia) o
``campo: {op: valor}`` con los operadores de ``OPERATORS``. Los valores que
empiezan por ``$`` se resuelven contra ``lists.yml`` (listas de permitidos).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from soc_lab.schema import SEVERITY_ORDER, Alert, Event, format_ts

RULES_DIR = Path(__file__).parent / "rules"
LISTS_FILE = Path(__file__).parent / "lists.yml"
VALID_TYPES = {"threshold", "distinct", "sequence"}
DURATION_RE = re.compile(r"^(\d+)([smh])$")


def parse_duration(value: str) -> timedelta:
    m = DURATION_RE.match(str(value))
    if not m:
        raise ValueError(f"duración inválida: {value!r} (usa 90s, 5m, 2h)")
    amount, unit = int(m[1]), m[2]
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours"}[unit]: amount})


# --------------------------------------------------------------------------
# Filtros
# --------------------------------------------------------------------------
def _in_cidr(value: Any, cidrs: Any) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    cidrs = cidrs if isinstance(cidrs, list) else [cidrs]
    return any(ip in ipaddress.ip_network(c) for c in cidrs)


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "in": lambda a, b: a in _as_list(b),
    "not_in": lambda a, b: a not in _as_list(b),
    "contains_any": lambda a, b: a is not None and any(s.lower() in str(a).lower() for s in _as_list(b)),
    "startswith": lambda a, b: a is not None and any(str(a).lower().startswith(s.lower()) for s in _as_list(b)),
    "cidr": _in_cidr,
    "not_cidr": lambda a, b: bool(a) and not _in_cidr(a, b),
    "gte": lambda a, b: a is not None and a >= b,
    "lte": lambda a, b: a is not None and a <= b,
    "exists": lambda a, b: (a is not None) == bool(b),
}


class Filter:
    def __init__(self, spec: dict[str, Any] | None, lists: dict[str, list]):
        self.conditions: list[tuple[str, str, Any]] = []
        for field_name, cond in (spec or {}).items():
            if isinstance(cond, dict):
                for op, value in cond.items():
                    if op not in OPERATORS:
                        raise ValueError(f"operador desconocido: {op}")
                    self.conditions.append((field_name, op, self._resolve(value, lists)))
            elif isinstance(cond, list):
                self.conditions.append((field_name, "in", self._resolve(cond, lists)))
            else:
                self.conditions.append((field_name, "eq", self._resolve(cond, lists)))

    @staticmethod
    def _resolve(value: Any, lists: dict[str, list]) -> Any:
        if isinstance(value, str) and value.startswith("$"):
            name = value[1:]
            if name not in lists:
                raise KeyError(f"lista no definida en lists.yml: {name}")
            return lists[name]
        if isinstance(value, list):
            out: list = []
            for item in value:
                resolved = Filter._resolve(item, lists)
                out.extend(resolved if isinstance(item, str) and item.startswith("$") else [resolved])
            return out
        return value

    def matches(self, event: Event) -> bool:
        return all(OPERATORS[op](event.get(f), v) for f, op, v in self.conditions)


# --------------------------------------------------------------------------
# Reglas
# --------------------------------------------------------------------------
@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    tactics: list[str]
    techniques: list[dict[str, str]]
    logic: dict[str, Any]
    summary: str
    data_sources: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    triage: list[str] = field(default_factory=list)
    response: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    exceptions: list[dict[str, Any]] = field(default_factory=list)
    severity_overrides: list[dict[str, Any]] = field(default_factory=list)
    status: str = "stable"
    path: str = ""
    # Compilados
    _filter: Filter | None = None
    _exceptions: list[Filter] = field(default_factory=list)
    _overrides: list[tuple[Filter, str]] = field(default_factory=list)
    _steps: list[tuple[Filter, int]] = field(default_factory=list)

    @property
    def type(self) -> str:
        return self.logic["type"]

    @property
    def window(self) -> timedelta:
        return parse_duration(self.logic["window"])

    @property
    def group_by(self) -> list[str]:
        return list(self.logic.get("group_by", []))

    def compile(self, lists: dict[str, list]) -> "Rule":
        if self.type not in VALID_TYPES:
            raise ValueError(f"{self.id}: tipo de lógica inválido {self.type!r}")
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"{self.id}: severidad inválida {self.severity!r}")
        if not self.techniques:
            raise ValueError(f"{self.id}: toda regla debe mapear al menos una técnica ATT&CK")
        self._filter = Filter(self.logic.get("filter"), lists)
        self._exceptions = [Filter(e, lists) for e in self.exceptions]
        self._overrides = [(Filter(o["when"], lists), o["severity"]) for o in self.severity_overrides]
        if self.type == "sequence":
            steps = self.logic["steps"]
            if len(steps) != 2:
                raise ValueError(f"{self.id}: las secuencias admiten exactamente 2 pasos")
            self._steps = [(Filter(s.get("filter"), lists), int(s.get("min_count", 1))) for s in steps]
        self.window  # valida la duración
        return self

    def selects(self, event: Event) -> bool:
        assert self._filter is not None, "regla sin compilar"
        if not self._filter.matches(event):
            return False
        return not any(exc.matches(event) for exc in self._exceptions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "description": self.description,
            "severity": self.severity, "status": self.status, "tactics": self.tactics,
            "techniques": self.techniques, "logic": self.logic, "summary": self.summary,
            "data_sources": self.data_sources, "false_positives": self.false_positives,
            "triage": self.triage, "response": self.response, "references": self.references,
            "exceptions": self.exceptions, "severity_overrides": self.severity_overrides,
            "path": self.path,
        }


def load_lists(path: Path = LISTS_FILE) -> dict[str, list]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_rules(rules_dir: Path = RULES_DIR, lists: dict[str, list] | None = None) -> list[Rule]:
    lists = load_lists() if lists is None else lists
    rules = []
    for path in sorted(rules_dir.glob("*.yml")):
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        mitre = spec.pop("mitre")
        rule = Rule(tactics=mitre["tactics"], techniques=mitre["techniques"],
                    path=f"soc_lab/detection/rules/{path.name}", **spec)
        rules.append(rule.compile(lists))
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError(f"IDs de regla duplicados: {ids}")
    return rules


# --------------------------------------------------------------------------
# Evaluación
# --------------------------------------------------------------------------
def _group_key(rule: Rule, event: Event) -> tuple | None:
    key = tuple(event.get(f) for f in rule.group_by)
    return None if any(v is None for v in key) else key


def _sliding(rule: Rule, events: list[Event]) -> Iterable[list[Event]]:
    """Ventanas deslizantes para ``threshold`` y ``distinct``."""
    window, threshold = rule.window, int(rule.logic["threshold"])
    distinct_field = rule.logic.get("distinct_field")
    n, start, j = len(events), 0, 0
    values: Counter = Counter()
    while j < n:
        while events[j].timestamp - events[start].timestamp > window:
            if distinct_field:
                values[events[start].get(distinct_field)] -= 1
                if values[events[start].get(distinct_field)] <= 0:
                    del values[events[start].get(distinct_field)]
            start += 1
        if distinct_field:
            values[events[j].get(distinct_field)] += 1
            met = len(values) >= threshold
        else:
            met = j - start + 1 >= threshold
        if met:
            end = j
            while end + 1 < n and events[end + 1].timestamp - events[end].timestamp <= window:
                end += 1
            yield events[start:end + 1]
            start = j = end + 1
            values.clear()
            continue
        j += 1


def _sequence(rule: Rule, events: list[Event]) -> Iterable[list[Event]]:
    (first, min_count), (second, _) = rule._steps
    window = rule.window
    recent: deque[Event] = deque()
    current: list[Event] | None = None
    seen: set[int] = set()
    last_activity = None  # último evento del ataque en curso
    for event in events:
        while recent and event.timestamp - recent[0].timestamp > window:
            recent.popleft()
        ongoing = current is not None and event.timestamp - last_activity <= window
        if first.matches(event):
            recent.append(event)
            if ongoing:
                last_activity = event.timestamp
        elif second.matches(event) and (ongoing or len(recent) >= min_count):
            if not ongoing:
                # Nuevo ataque: se cierra la alerta anterior (si la hay).
                if current:
                    yield sorted(current, key=lambda e: e.timestamp)
                current, seen = [], set()
            # Un éxito durante un ataque en curso pertenece a la misma alerta.
            current.extend(e for e in recent if id(e) not in seen)
            current.append(event)
            seen.update(id(e) for e in current)
            last_activity = event.timestamp
    if current:
        yield sorted(current, key=lambda e: e.timestamp)


class _Context(dict):
    def __missing__(self, key: str) -> str:
        return f"{{{key}}}"


def _top(values: Iterable[Any], limit: int = 3) -> str:
    counts = Counter(v for v in values if v is not None)
    items = [str(v) for v, _ in counts.most_common(limit)]
    extra = len(counts) - len(items)
    return ", ".join(items) + (f" (+{extra})" if extra > 0 else "")


def build_alert(rule: Rule, key: tuple, evidence: list[Event]) -> Alert:
    first, last = evidence[0].timestamp, evidence[-1].timestamp
    group = dict(zip(rule.group_by, key))
    entities = {
        name: sorted({str(v) for v in (e.get(attr) for e in evidence) if v is not None})
        for name, attr in (("users", "user"), ("src_ips", "src_ip"), ("dst_ips", "dst_ip"),
                           ("hosts", "host"), ("services", "service_name"))
    }
    entities = {k: v for k, v in entities.items() if v}
    severity = rule.severity
    for flt, sev in rule._overrides:
        if any(flt.matches(e) for e in evidence) and SEVERITY_ORDER[sev] > SEVERITY_ORDER[severity]:
            severity = sev

    ctx = _Context(group)
    ctx.update(
        count=len(evidence),
        distinct=len({e.get(rule.logic.get("distinct_field", "")) for e in evidence}),
        users=_top(e.user for e in evidence),
        distinct_users=len(entities.get("users", [])),
        hosts=_top(e.host for e in evidence),
        src_ips=_top(e.src_ip for e in evidence),
        dst_ips=_top(e.dst_ip for e in evidence),
        ports=_top((e.dst_port for e in evidence), limit=8),
        service=_top(e.service_name for e in evidence),
        image_path=evidence[-1].get("extra.image_path") or "",
        first_seen=format_ts(first), last_seen=format_ts(last),
        duration_min=round((last - first).total_seconds() / 60, 1),
    )
    if rule.type == "sequence":
        second = rule._steps[1][0]
        winners = [e for e in evidence if second.matches(e)]
        ctx.update(failures=len(evidence) - len(winners),
                   success_users=_top(e.user for e in winners), successes=len(winners))

    digest = hashlib.sha1(f"{rule.id}|{key}|{format_ts(first)}".encode()).hexdigest()[:8]
    return Alert(
        alert_id=f"{rule.id}-{digest}",
        rule_id=rule.id,
        rule_name=rule.name,
        severity=severity,
        tactic=rule.tactics,
        techniques=rule.techniques,
        first_seen=first,
        last_seen=last,
        group={k: v for k, v in group.items()},
        entities=entities,
        event_count=len(evidence),
        summary=rule.summary.strip().format_map(ctx),
        evidence=evidence,
    )


def run_rule(rule: Rule, events: list[Event]) -> list[Alert]:
    groups: dict[tuple, list[Event]] = defaultdict(list)
    for event in events:
        # En secuencias el filtro base delimita el universo y los pasos se
        # evalúan después; las excepciones aplican igual a todos los tipos.
        if not rule.selects(event):
            continue
        key = _group_key(rule, event)
        if key is not None:
            groups[key].append(event)

    alerts = []
    for key, group_events in groups.items():
        group_events.sort(key=lambda e: e.timestamp)
        matcher = _sequence if rule.type == "sequence" else _sliding
        for evidence in matcher(rule, group_events):
            alerts.append(build_alert(rule, key, evidence))
    return alerts


def run_rules(rules: list[Rule], events: list[Event]) -> list[Alert]:
    alerts = [a for rule in rules for a in run_rule(rule, events)]
    alerts.sort(key=lambda a: (a.first_seen, a.rule_id, a.alert_id))
    return alerts
