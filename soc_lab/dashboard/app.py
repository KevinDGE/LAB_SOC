"""Dashboard web del SOC (Flask).

Rutas HTML: ``/`` resumen, ``/alerts`` (filtrable), ``/alerts/<id>``,
``/rules``, ``/rules/<id>``. API JSON: ``/api/stats``, ``/api/alerts``,
``/api/alerts/<id>``, ``/api/rules``, ``/healthz``.

Los datos se cargan una vez al arrancar desde el directorio de datos generado
por el pipeline (``python -m soc_lab all``).
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from markupsafe import Markup, escape

from flask import Flask, abort, jsonify, render_template, request

from soc_lab import __version__, pipeline
from soc_lab.dashboard import charts
from soc_lab.detection.engine import load_rules
from soc_lab.schema import SEVERITY_ORDER, Alert


class LabData:
    """Contenedor en memoria de todo lo que el dashboard muestra."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.events = pipeline.load_events(data_dir)
        self.alerts, self.metrics = pipeline.load_alerts(data_dir)
        self.rules = load_rules()
        self.rules_by_id = {r.id: r for r in self.rules}
        self.alerts_by_id = {a.alert_id: a for a in self.alerts}
        self.cases = pipeline.load_cases(data_dir)
        self.case_by_alert = {aid: c for c in self.cases for aid in c["alert_ids"]}

    def filter_alerts(self, args) -> list[Alert]:
        result = self.alerts
        if sev := args.get("severity"):
            result = [a for a in result if a.severity == sev]
        if rule := args.get("rule"):
            result = [a for a in result if a.rule_id == rule]
        if tactic := args.get("tactic"):
            result = [a for a in result if tactic in a.tactic]
        if q := args.get("q", "").strip().lower():
            result = [a for a in result if q in a.summary.lower()
                      or any(q in v.lower() for vals in a.entities.values() for v in vals)]
        if args.get("sort") == "severity":
            result = sorted(result, key=lambda a: (-SEVERITY_ORDER[a.severity], a.first_seen))
        return result


def create_app(data_dir: Path | str = "data") -> Flask:
    app = Flask(__name__)
    data = LabData(Path(data_dir))
    app.config["LAB_DATA"] = data

    # Globales (visibles también dentro de las macros importadas).
    app.jinja_env.globals.update(
        version=__version__,
        severity_labels=charts.SEVERITY_LABELS,
        severity_icons=charts.SEVERITY_ICONS,
    )

    @app.context_processor
    def inject_nav():
        return {"nav": request.endpoint}

    @app.template_filter("md_inline")
    def md_inline(text: str) -> Markup:
        """Markdown en línea mínimo (**negrita**, *cursiva*, `código`) sobre texto escapado."""
        html = str(escape(text))
        html = re.sub(r"`([^`]+)`", r"<code>\1</code>", html)
        html = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", html)
        html = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", html)
        return Markup(html)

    @app.template_filter("ts_hms")
    def ts_hms(value: str) -> str:
        return value[11:19]

    @app.template_filter("hms")
    def hms(ts):
        return ts.strftime("%H:%M:%S")

    # ------------------------------------------------------------------ HTML
    @app.get("/")
    def overview():
        return render_template(
            "overview.html",
            data=data,
            severities=charts.severity_counts(data.alerts),
            volume=charts.events_per_hour(data.events),
            timeline=charts.alert_timeline(data.alerts, data.rules, data.events),
            matrix=charts.attack_matrix(data.rules, data.alerts),
            top_sources=charts.top_sources(data.alerts),
            day=charts.day_bounds(data.events)[0],
        )

    @app.get("/alerts")
    def alerts():
        tactics = sorted({t for a in data.alerts for t in a.tactic},
                         key=lambda t: charts.TACTIC_ORDER.index(t) if t in charts.TACTIC_ORDER else 99)
        return render_template("alerts.html", data=data, alerts=data.filter_alerts(request.args),
                               args=request.args, tactics=tactics)

    @app.get("/alerts/<alert_id>")
    def alert_detail(alert_id: str):
        alert = data.alerts_by_id.get(alert_id) or abort(404)
        return render_template("alert_detail.html", alert=alert, rule=data.rules_by_id[alert.rule_id],
                               case=data.case_by_alert.get(alert_id))

    @app.get("/rules")
    def rules():
        fired = Counter(a.rule_id for a in data.alerts)
        return render_template("rules.html", rules=data.rules, fired=fired)

    @app.get("/rules/<rule_id>")
    def rule_detail(rule_id: str):
        rule = data.rules_by_id.get(rule_id) or abort(404)
        alerts = [a for a in data.alerts if a.rule_id == rule_id]
        return render_template("rule_detail.html", rule=rule, alerts=alerts)

    @app.get("/cases")
    def cases():
        return render_template("cases.html", cases=data.cases)

    @app.get("/cases/<case_id>")
    def case_detail(case_id: str):
        case = next((c for c in data.cases if c["case_id"] == case_id), None) or abort(404)
        alerts = [data.alerts_by_id[a] for a in case["alert_ids"] if a in data.alerts_by_id]
        return render_template("case_detail.html", case=case, alerts=alerts)

    @app.errorhandler(404)
    def not_found(_):
        return render_template("404.html"), 404

    # ------------------------------------------------------------------- API
    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "events": len(data.events), "alerts": len(data.alerts)}

    @app.get("/api/stats")
    def api_stats():
        return jsonify({
            "events": len(data.events),
            "events_by_source": Counter(e.source for e in data.events),
            "alerts": len(data.alerts),
            "alerts_by_severity": Counter(a.severity for a in data.alerts),
            "alerts_by_rule": Counter(a.rule_id for a in data.alerts),
            "cases": len(data.cases),
            "metrics": data.metrics,
        })

    @app.get("/api/alerts")
    def api_alerts():
        return jsonify([a.to_dict(include_evidence=False) for a in data.filter_alerts(request.args)])

    @app.get("/api/alerts/<alert_id>")
    def api_alert(alert_id: str):
        alert = data.alerts_by_id.get(alert_id) or abort(404)
        return jsonify(alert.to_dict())

    @app.get("/api/rules")
    def api_rules():
        return jsonify([r.to_dict() for r in data.rules])

    @app.get("/api/cases")
    def api_cases():
        return jsonify(data.cases)

    return app
