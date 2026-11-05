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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soc_lab", description="Laboratorio SOC con datos simulados")
    parser.add_argument("--data", type=Path, default=Path("data"), help="directorio de datos (default: data)")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="genera logs crudos simulados y los normaliza")
    gen.add_argument("--seed", type=int, default=DEFAULT_SEED)
    gen.set_defaults(func=cmd_generate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
