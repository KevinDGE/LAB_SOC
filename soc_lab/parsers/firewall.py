"""Parser del firewall perimetral/interno ``fw01`` (formato clave=valor).

Ejemplo::

    2026-10-14T02:47:03Z fw01 action=deny proto=tcp src=203.0.113.77 spt=40112 dst=10.10.2.10 dpt=3389 bytes=0 rule=default-deny
"""

from __future__ import annotations

from soc_lab.schema import Event, parse_ts

OUTCOMES = {"allow": "allowed", "deny": "denied"}


def parse_line(line: str) -> Event | None:
    line = line.rstrip("\n")
    parts = line.split(" ")
    if len(parts) < 3:
        return None
    ts, host, *pairs = parts
    fields = dict(p.split("=", 1) for p in pairs if "=" in p)
    if "action" not in fields or "src" not in fields:
        return None
    return Event(
        timestamp=parse_ts(ts),
        source="firewall",
        event_code="fw_conn",
        category="network",
        action="connection",
        outcome=OUTCOMES.get(fields["action"], fields["action"]),
        host=host,
        src_ip=fields["src"],
        src_port=int(fields["spt"]) if "spt" in fields else None,
        dst_ip=fields.get("dst"),
        dst_port=int(fields["dpt"]) if "dpt" in fields else None,
        protocol=fields.get("proto"),
        raw=line,
        extra={"bytes": int(fields.get("bytes", 0)), "rule": fields.get("rule", "")},
    )
