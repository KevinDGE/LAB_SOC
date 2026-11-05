"""Construye los casos: agrupa alertas, arma la línea de tiempo y escribe reportes.

Salidas:

* ``data/cases.json`` — consumido por el dashboard.
* ``reports/CASE-00X.md`` — reporte de incidente listo para leer en GitHub.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from soc_lab.cases.definitions import CASES
from soc_lab.dashboard.charts import SEVERITY_LABELS, TACTIC_ORDER
from soc_lab.detection.engine import Filter, Rule
from soc_lab.schema import Alert, Event, format_ts, parse_ts

INTERNAL = ipaddress.ip_network("10.0.0.0/8")


def _is_external(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) not in INTERNAL
    except ValueError:
        return False


class _Ctx(dict):
    def __missing__(self, key: str) -> str:
        return "—"


def _hms(ts: datetime) -> str:
    return ts.strftime("%H:%M:%S")


def _event_ctx(event: Event) -> _Ctx:
    data = event.to_dict()
    ctx = _Ctx({k: ("—" if v is None else v) for k, v in data.items() if k != "extra"})
    ctx["extra"] = SimpleNamespace(**{k: ("—" if v is None else v) for k, v in event.extra.items()})
    ctx["mb"] = f"{event.extra.get('bytes', 0) / 1_000_000:.1f}"
    return ctx


def _aggregate_ctx(events: list[Event]) -> _Ctx:
    gaps = [(b.timestamp - a.timestamp).total_seconds() for a, b in zip(events, events[1:])]
    users = Counter(e.user for e in events if e.user)
    return _Ctx(
        count=len(events),
        first=_hms(events[0].timestamp),
        last=_hms(events[-1].timestamp),
        users=", ".join(sorted(users)),
        distinct_users=len(users),
        dst_ports=", ".join(str(p) for p in sorted({e.dst_port for e in events if e.dst_port})),
        dst_ips=", ".join(sorted({e.dst_ip for e in events if e.dst_ip})),
        bytes_mb=f"{sum(e.extra.get('bytes', 0) for e in events) / 1_000_000:,.0f}",
        avg_gap=f"{sum(gaps) / len(gaps):.0f}" if gaps else "0",
    )


def _technique_catalog(rules: list[Rule], extra: list[dict]) -> dict[str, dict]:
    catalog: dict[str, dict] = {}
    for rule in rules:
        for t in rule.techniques:
            catalog.setdefault(t["id"], {"id": t["id"], "name": t["name"],
                                         "tactic": t.get("tactic", rule.tactics[0])})
    for t in extra:
        catalog.setdefault(t["id"], dict(t))
    return catalog


def build_case(spec: dict, alerts: list[Alert], events: list[Event], rules: list[Rule]) -> dict[str, Any]:
    start, end = (parse_ts(t) for t in spec["window"])
    pivots = set(spec["pivots"])
    lists: dict[str, list] = {}
    in_window = [e for e in events if start <= e.timestamp <= end]

    case_alerts = [
        a for a in alerts
        if a.first_seen <= end and a.last_seen >= start
        and pivots & {v for vals in a.entities.values() for v in vals}
    ]

    timeline: list[dict] = []
    for a in case_alerts:
        timeline.append({
            "ts": format_ts(a.first_seen), "end": format_ts(a.last_seen), "kind": "alert",
            "title": f"{a.rule_id} · {a.rule_name}", "detail": a.summary, "severity": a.severity,
            "techniques": [t["id"] for t in a.techniques], "alert_id": a.alert_id, "source": "alerta",
        })

    context_events: list[Event] = []
    for item in spec["context"]:
        flt = Filter(item["filter"], lists)
        scope = in_window
        if "window" in item:  # sub-ventana opcional del elemento de contexto
            lo, hi = (parse_ts(t) for t in item["window"])
            scope = [e for e in in_window if lo <= e.timestamp <= hi]
        matched = [e for e in scope if flt.matches(e)]
        if not matched:
            raise ValueError(f"{spec['case_id']}: el contexto «{item['title']}» no encontró eventos")
        context_events.extend(matched)
        techniques = [item["technique"]] if item.get("technique") else []
        if item.get("aggregate"):
            timeline.append({
                "ts": format_ts(matched[0].timestamp), "end": format_ts(matched[-1].timestamp),
                "kind": "activity", "title": item["title"],
                "detail": item["detail"].format_map(_aggregate_ctx(matched)),
                "techniques": techniques, "source": matched[0].source, "count": len(matched),
            })
        else:
            for e in matched:
                timeline.append({
                    "ts": format_ts(e.timestamp), "kind": "event", "title": item["title"],
                    "detail": item["detail"].format_map(_event_ctx(e)), "techniques": techniques,
                    "source": e.source, "raw": e.raw, "key": item.get("key", False),
                })
    order = {"activity": 0, "event": 1, "alert": 2}
    timeline.sort(key=lambda t: (t["ts"], order[t["kind"]], t["title"]))

    # Evidencia cruda citada en el reporte.
    samples = []
    for sample in spec["evidence_samples"]:
        flt = Filter(sample["filter"], lists)
        samples.extend(e.raw for e in [e for e in in_window if flt.matches(e)][: sample["limit"]])

    # Mapeo ATT&CK: reglas que dispararon + técnicas observadas en contexto.
    catalog = _technique_catalog(rules, spec.get("extra_techniques", []))
    mapping: dict[str, dict] = {}
    for a in case_alerts:
        for t in a.techniques:
            row = mapping.setdefault(t["id"], {**catalog[t["id"]], "evidence": set()})
            row["evidence"].add(a.rule_id)
    for item in spec["context"]:
        if item.get("technique"):
            row = mapping.setdefault(item["technique"], {**catalog[item["technique"]], "evidence": set()})
            row["evidence"].add("contexto (sin alerta)" if not row["evidence"] else "contexto")
    for t in spec.get("extra_techniques", []):
        mapping.setdefault(t["id"], {**catalog[t["id"]], "evidence": {"inferido por el analista"}})
    attack = sorted(
        ({**row, "evidence": sorted(row["evidence"])} for row in mapping.values()),
        key=lambda r: (TACTIC_ORDER.index(r["tactic"]) if r["tactic"] in TACTIC_ORDER else 99, r["id"]),
    )

    # Indicadores de compromiso.
    all_events = [e for a in case_alerts for e in a.evidence] + context_events
    ips: dict[str, dict] = {}
    for e in all_events:
        for ip, role in ((e.src_ip, "origen del ataque"), (e.dst_ip, "destino externo (C2 / staging)")):
            if _is_external(ip):
                row = ips.setdefault(ip, {"value": ip, "type": "IPv4 externa (RFC 5737)", "role": role,
                                          "first": e.timestamp, "last": e.timestamp})
                row["first"], row["last"] = min(row["first"], e.timestamp), max(row["last"], e.timestamp)
    accounts = sorted({e.user for a in case_alerts for e in a.evidence
                       if e.category == "authentication" and e.outcome == "success" and e.user})
    services = sorted({e.service_name for a in case_alerts for e in a.evidence if e.service_name})
    iocs = [{**row, "first": format_ts(row["first"]), "last": format_ts(row["last"])}
            for row in sorted(ips.values(), key=lambda r: r["first"])]
    iocs += [{"value": u, "type": "Cuenta", "role": "credencial comprometida"} for u in accounts]
    iocs += [{"value": s, "type": "Servicio Windows", "role": "ejecución remota"} for s in services]

    first_activity = parse_ts(timeline[0]["ts"])
    last_activity = max(parse_ts(t.get("end", t["ts"])) for t in timeline)
    malicious = [t for t in timeline if t["kind"] != "event" or t["techniques"]]
    first_malicious = parse_ts(malicious[0]["ts"])
    first_alert = min((a.first_seen for a in case_alerts), default=None)
    return {
        "case_id": spec["case_id"],
        "title": spec["title"],
        "severity": spec["severity"],
        "status": spec["status"],
        "classification": spec["classification"],
        "summary": spec["summary"],
        "analysis": spec["analysis"],
        "scope": spec["scope"],
        "response": spec["response"],
        "lessons": spec["lessons"],
        "alert_ids": [a.alert_id for a in case_alerts],
        "alert_rules": sorted({a.rule_id for a in case_alerts}),
        "timeline": timeline,
        "attack": attack,
        "iocs": iocs,
        "evidence_samples": samples,
        "metrics": {
            "first_activity": format_ts(first_activity),
            "first_malicious": format_ts(first_malicious),
            "first_alert": format_ts(first_alert) if first_alert else None,
            "last_activity": format_ts(last_activity),
            "duration_min": round((last_activity - first_malicious).total_seconds() / 60),
            "time_to_detect_min": round((first_alert - first_malicious).total_seconds() / 60, 1) if first_alert else None,
            "alerts": len(case_alerts),
            "events": len({id(e) for e in all_events}),
        },
    }


def build_cases(alerts: list[Alert], events: list[Event], rules: list[Rule]) -> list[dict]:
    return [build_case(spec, alerts, events, rules) for spec in CASES]


# --------------------------------------------------------------------------
# Reporte Markdown
# --------------------------------------------------------------------------
def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def render_report(case: dict, alerts_by_id: dict[str, Alert]) -> str:
    m = case["metrics"]
    day = m["first_activity"][:10]
    out = [
        f"# {case['case_id']} — {case['title']}",
        "",
        "> **Datos 100 % simulados.** Organización ficticia (Acme Andina S.A.); las IPs externas pertenecen "
        "a rangos de documentación RFC 5737. Reporte generado con `python -m soc_lab cases`.",
        "",
        "| Campo | Valor |",
        "|---|---|",
        f"| Severidad | {SEVERITY_LABELS[case['severity']]} |",
        f"| Estado | {case['status']} |",
        f"| Clasificación | {case['classification']} |",
        f"| Fecha | {day} (UTC) |",
        f"| Primera actividad maliciosa | {m['first_malicious'][11:19]} UTC |",
        f"| Primera alerta | {m['first_alert'][11:19] if m['first_alert'] else '—'} UTC "
        f"(tiempo de detección: {m['time_to_detect_min']} min) |",
        f"| Última actividad | {m['last_activity'][11:19]} UTC (duración: {m['duration_min']} min) |",
        f"| Alertas correlacionadas | {m['alerts']} ({', '.join(case['alert_rules'])}) |",
        f"| Eventos revisados | {m['events']} |",
        "",
        "## 1. Resumen ejecutivo",
        "",
        case["summary"],
        "",
        "## 2. Alcance",
        "",
        "**Activos afectados:**",
        "",
        *[f"- {h}" for h in case["scope"]["hosts"]],
        "",
        "**Cuentas afectadas:**",
        "",
        *[f"- {a}" for a in case["scope"]["accounts"]],
        "",
        f"**Fuera de alcance:** {case['scope']['not_affected']}",
        "",
        "## 3. Línea de tiempo (UTC)",
        "",
        "| Hora | Tipo | Evento | Detalle | ATT&CK |",
        "|---|---|---|---|---|",
    ]
    kinds = {"alert": "🚨 Alerta", "activity": "Actividad", "event": "Evento"}
    for t in case["timeline"]:
        when = t["ts"][11:19] + (f"–{t['end'][11:19]}" if t.get("end") and t["end"] != t["ts"] else "")
        title = t["title"]
        if t["kind"] == "alert":
            title = f"{title} ({SEVERITY_LABELS[t['severity']]})"
        out.append(f"| {when} | {kinds[t['kind']]} | {_md_escape(title)} | {_md_escape(t['detail'])} | "
                   f"{', '.join(t['techniques']) or '—'} |")

    out += ["", "## 4. Análisis técnico", ""]
    for paragraph in case["analysis"]:
        out += [paragraph, ""]
    out += ["**Evidencia cruda (extracto):**", "", "```text", *case["evidence_samples"], "```", ""]

    out += ["## 5. Mapeo MITRE ATT&CK", "", "| Táctica | Técnica | Evidencia |", "|---|---|---|"]
    for row in case["attack"]:
        link = f"https://attack.mitre.org/techniques/{row['id'].replace('.', '/')}/"
        out.append(f"| {row['tactic']} | [{row['id']}]({link}) {row['name']} | {', '.join(row['evidence'])} |")

    out += ["", "## 6. Indicadores de compromiso", "", "| Indicador | Tipo | Rol | Visto (UTC) |", "|---|---|---|---|"]
    for ioc in case["iocs"]:
        seen = f"{ioc['first'][11:19]}–{ioc['last'][11:19]}" if "first" in ioc else "—"
        out.append(f"| `{ioc['value']}` | {ioc['type']} | {ioc['role']} | {seen} |")

    out += ["", "## 7. Respuesta", ""]
    for phase, actions in case["response"].items():
        out += [f"**{phase}**", "", *[f"- [x] {a}" for a in actions], ""]

    out += ["## 8. Lecciones aprendidas y brechas de detección", "", *[f"- {l}" for l in case["lessons"]], ""]

    out += ["## 9. Alertas relacionadas", "", "| ID | Regla | Severidad | Inicio | Fin | Eventos |",
            "|---|---|---|---|---|---|"]
    for aid in case["alert_ids"]:
        a = alerts_by_id[aid]
        out.append(f"| `{a.alert_id}` | {a.rule_id} {a.rule_name} | {SEVERITY_LABELS[a.severity]} | "
                   f"{a.first_seen:%H:%M:%S} | {a.last_seen:%H:%M:%S} | {a.event_count} |")
    return "\n".join(out) + "\n"


def write_reports(cases: list[dict], alerts: list[Alert], reports_dir: Path) -> list[Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    by_id = {a.alert_id: a for a in alerts}
    paths = []
    for case in cases:
        path = reports_dir / f"{case['case_id']}.md"
        path.write_text(render_report(case, by_id), encoding="utf-8")
        paths.append(path)
    index = ["# Reportes de incidentes", "", "| Caso | Título | Severidad | Alertas | Duración |", "|---|---|---|---|---|"]
    for c in cases:
        index.append(f"| [{c['case_id']}]({c['case_id']}.md) | {c['title']} | {SEVERITY_LABELS[c['severity']]} | "
                     f"{c['metrics']['alerts']} | {c['metrics']['duration_min']} min |")
    (reports_dir / "README.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    return paths
