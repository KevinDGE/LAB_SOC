"""Geometría de los gráficos del dashboard (SVG generado en el servidor).

Los gráficos se calculan en Python y se dibujan con plantillas Jinja; no se
usa ninguna librería JS ni CDN, así el dashboard funciona sin Internet dentro
del contenedor. Los colores se referencian por rol (variables CSS) para que el
modo claro/oscuro se resuelva en la hoja de estilos.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from soc_lab.schema import SEVERITY_ORDER, Alert, Event, format_ts

SOURCES = [("firewall", "Firewall"), ("windows", "Windows"), ("sshd", "SSH")]
SEVERITY_LABELS = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Info"}
SEVERITY_ICONS = {"critical": "◆", "high": "▲", "medium": "●", "low": "○", "info": "○"}

# Orden de tácticas según la matriz Enterprise de ATT&CK.
TACTIC_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]


def _nice_max(value: int) -> int:
    """Máximo del eje redondeado para que los 4 intervalos sean números limpios."""
    for mag in (1, 10, 100, 1000, 10000, 100000):
        for step in (1, 2, 2.5, 5):
            if value <= step * mag * 4:
                return int(step * mag * 4)
    return value


def _rounded_top(x: float, y: float, w: float, h: float, r: float = 4) -> str:
    """Rectángulo con el extremo de datos redondeado y la base recta."""
    r = min(r, w / 2, h)
    return (f"M{x:.1f},{y + h:.1f} V{y + r:.1f} Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} "
            f"H{x + w - r:.1f} Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} V{y + h:.1f} Z")


def day_bounds(events: list[Event]) -> tuple[datetime, datetime]:
    start = min(e.timestamp for e in events).replace(hour=0, minute=0, second=0)
    return start, start + timedelta(days=1)


def events_per_hour(events: list[Event]) -> dict:
    """Columnas apiladas por fuente, una por hora."""
    start, _ = day_bounds(events)
    counts: dict[int, Counter] = defaultdict(Counter)
    for e in events:
        counts[int((e.timestamp - start).total_seconds() // 3600)][e.source] += 1

    width, height, left, right, top, bottom = 760, 220, 44, 8, 12, 28
    plot_w, plot_h = width - left - right, height - top - bottom
    totals = [sum(counts[h].values()) for h in range(24)]
    ymax = _nice_max(max(totals) or 1)
    band = plot_w / 24
    bar_w = min(24, band - 6)
    gap = 2

    bars, rows = [], []
    for hour in range(24):
        x = left + hour * band + (band - bar_w) / 2
        y_cursor = top + plot_h
        stack = [(key, counts[hour][key]) for key, _ in SOURCES if counts[hour][key]]
        segments = []
        for i, (key, value) in enumerate(stack):
            h = value / ymax * plot_h
            seg_h = max(h - (gap if i else 0), 1)
            y = y_cursor - h
            is_top = i == len(stack) - 1
            segments.append({
                "key": key, "value": value,
                "path": _rounded_top(x, y, bar_w, seg_h) if is_top else
                        f"M{x:.1f},{y + seg_h:.1f} V{y:.1f} H{x + bar_w:.1f} V{y + seg_h:.1f} Z",
            })
            y_cursor = y
        bars.append({
            "hour": hour, "x": round(x, 1), "w": round(bar_w, 1), "segments": segments,
            "hit_x": round(left + hour * band, 1), "hit_w": round(band, 1),
            "total": totals[hour],
            "tip": [f"{counts[hour][k]:,} {label}" for k, label in SOURCES],
        })
        rows.append({"hour": f"{hour:02d}:00", **{k: counts[hour][k] for k, _ in SOURCES}, "total": totals[hour]})

    ticks = [{"y": round(top + plot_h - v / ymax * plot_h, 1), "label": f"{v:,}"}
             for v in range(0, ymax + 1, ymax // 4)]
    xticks = [{"x": round(left + h * band + band / 2, 1), "label": f"{h:02d}"} for h in range(0, 24, 3)]
    return {"width": width, "height": height, "left": left, "right": width - right,
            "baseline": top + plot_h, "bars": bars, "ticks": ticks, "xticks": xticks,
            "sources": SOURCES, "rows": rows,
            "totals": {k: sum(r[k] for r in rows) for k, _ in SOURCES}}


def alert_timeline(alerts: list[Alert], rules: list, events: list[Event]) -> dict:
    """Carriles por regla con la duración de cada alerta sobre el día."""
    start, end = day_bounds(events)
    span = (end - start).total_seconds()
    width, left, right, top, lane = 1160, 250, 12, 8, 28
    plot_w = width - left - right
    names = {r.id: r.name for r in rules}
    rule_ids = [r.id for r in rules]
    height = top + lane * len(rule_ids) + 28

    def xpos(ts: datetime) -> float:
        return left + (ts - start).total_seconds() / span * plot_w

    lanes = [{"rule_id": rid, "name": names[rid], "y": top + i * lane} for i, rid in enumerate(rule_ids)]
    marks = []
    for a in alerts:
        i = rule_ids.index(a.rule_id)
        x1, x2 = xpos(a.first_seen), xpos(a.last_seen)
        w = max(x2 - x1, 8)
        marks.append({
            "alert_id": a.alert_id, "severity": a.severity, "x": round(min(x1, left + plot_w - w), 1),
            "y": top + i * lane + 8, "w": round(w, 1), "h": 12,
            "tip_value": f"{a.first_seen:%H:%M}–{a.last_seen:%H:%M} UTC",
            "tip_label": f"{a.rule_id} · {SEVERITY_LABELS[a.severity]}",
            "tip_extra": a.summary,
        })
    xticks = [{"x": round(left + h / 24 * plot_w, 1), "label": f"{h:02d}:00"} for h in range(0, 25, 3)]
    return {"width": width, "height": height, "left": left, "right": left + plot_w,
            "lanes": lanes, "marks": marks, "xticks": xticks, "bottom": top + lane * len(rule_ids),
            "lane_h": lane}


def attack_matrix(rules: list, alerts: list[Alert]) -> list[dict]:
    """Matriz ATT&CK: técnicas cubiertas por reglas y alertas observadas."""
    alert_counts: Counter = Counter()
    for a in alerts:
        for t in a.techniques:
            alert_counts[t["id"]] += 1
    columns: dict[str, dict[str, dict]] = defaultdict(dict)
    for r in rules:
        for t in r.techniques:
            tactic = t.get("tactic", r.tactics[0])
            cell = columns[tactic].setdefault(t["id"], {"id": t["id"], "name": t["name"], "rules": []})
            cell["rules"].append(r.id)
    peak = max(alert_counts.values() or [1])
    out = []
    for tactic in TACTIC_ORDER:
        if tactic not in columns:
            continue
        cells = []
        for cell in sorted(columns[tactic].values(), key=lambda c: c["id"]):
            count = alert_counts[cell["id"]]
            # Rampa secuencial azul (100 → 600) según alertas observadas.
            level = 0 if count == 0 else 1 + round((count / peak) * 4)
            cells.append({**cell, "alerts": count, "level": min(level, 5)})
        out.append({"tactic": tactic, "cells": cells})
    return out


def severity_counts(alerts: list[Alert]) -> list[dict]:
    counts = Counter(a.severity for a in alerts)
    return [{"key": s, "label": SEVERITY_LABELS[s], "icon": SEVERITY_ICONS[s], "count": counts[s]}
            for s in sorted(SEVERITY_LABELS, key=SEVERITY_ORDER.get, reverse=True) if s != "info"]


def top_sources(alerts: list[Alert], limit: int = 6) -> list[dict]:
    counter: Counter = Counter()
    worst: dict[str, str] = {}
    for a in alerts:
        for ip in a.entities.get("src_ips", []):
            counter[ip] += 1
            if SEVERITY_ORDER[a.severity] > SEVERITY_ORDER.get(worst.get(ip, "info"), 0):
                worst[ip] = a.severity
    return [{"ip": ip, "alerts": n, "severity": worst[ip]} for ip, n in counter.most_common(limit)]


def fmt(ts: datetime) -> str:
    return format_ts(ts)
