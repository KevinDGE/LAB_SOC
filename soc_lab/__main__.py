"""CLI del laboratorio: ``python -m soc_lab <comando>``."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from soc_lab import pipeline
from soc_lab.simulator.generator import DEFAULT_SEED, generate


def cmd_generate(args: argparse.Namespace) -> None:
    manifest = generate(pipeline.raw_dir(args.data), seed=args.seed)
    print(f"[generate] semilla={manifest['seed']} día={manifest['day']}")
    for name, count in manifest["files"].items():
        print(f"  {name:<15} {count:>6} registros")
    events = pipeline.normalize(args.data)
    by_source = Counter(e.source for e in events)
    print(f"[normalize] {len(events)} eventos → {pipeline.events_path(args.data)}  {dict(by_source)}")


def cmd_detect(args: argparse.Namespace) -> None:
    alerts, metrics = pipeline.detect(args.data)
    print(f"[detect] {len(alerts)} alertas → {pipeline.alerts_path(args.data)}")
    for alert in alerts:
        print(f"  {alert.first_seen:%H:%M:%S}  {alert.severity:<8} {alert.rule_id}  {alert.summary}")
    print("[evaluate]")
    for sc in metrics["scenarios"]:
        status = "OK " if not sc["missed_rules"] else "GAP"
        print(f"  {status} {sc['scenario_id']}  disparadas={sc['fired_rules']}  faltantes={sc['missed_rules']}")
    print(f"  alertas atribuidas a escenarios: {metrics['alerts_attributed']}/{metrics['alerts_total']}"
          f"  no atribuidas: {metrics['unattributed_alerts']}")


def cmd_docs(args: argparse.Namespace) -> None:
    from soc_lab.detection.docs import write_docs

    print(f"[docs] {write_docs(Path('docs/detection-rules.md'))}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soc_lab", description="Laboratorio SOC con datos simulados")
    parser.add_argument("--data", type=Path, default=Path("data"), help="directorio de datos (default: data)")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="genera logs crudos simulados y los normaliza")
    gen.add_argument("--seed", type=int, default=DEFAULT_SEED)
    gen.set_defaults(func=cmd_generate)

    det = sub.add_parser("detect", help="ejecuta las reglas sobre los eventos normalizados")
    det.set_defaults(func=cmd_detect)

    docs = sub.add_parser("docs", help="regenera docs/detection-rules.md desde los YAML")
    docs.set_defaults(func=cmd_docs)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
