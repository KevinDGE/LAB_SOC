"""Parser de líneas de OpenSSH (``sshd``) en formato syslog con timestamp ISO.

Ejemplos de entrada::

    2026-10-14T03:05:12Z srv-web-01 sshd[4312]: Failed password for invalid user admin from 203.0.113.77 port 51234 ssh2
    2026-10-14T03:21:14Z srv-web-01 sshd[4999]: Accepted password for deploy from 203.0.113.77 port 40022 ssh2
"""

from __future__ import annotations

import re

from soc_lab.schema import Event, parse_ts
from soc_lab.simulator.topology import asset_by_name

LINE_RE = re.compile(
    r"^(?P<ts>\S+) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<msg>.*)$"
)
AUTH_RE = re.compile(
    r"^(?P<result>Failed|Accepted) (?P<method>password|publickey) for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2$"
)


def parse_line(line: str) -> Event | None:
    """Devuelve un ``Event`` o ``None`` si la línea no es de autenticación."""
    line = line.rstrip("\n")
    m = LINE_RE.match(line)
    if not m:
        return None
    auth = AUTH_RE.match(m["msg"])
    if not auth:
        return None
    success = auth["result"] == "Accepted"
    host = m["host"]
    try:
        dst_ip = asset_by_name(host).ip
    except KeyError:
        dst_ip = None
    return Event(
        timestamp=parse_ts(m["ts"]),
        source="sshd",
        event_code="sshd_accepted" if success else "sshd_failed",
        category="authentication",
        action="logon_success" if success else "logon_failure",
        outcome="success" if success else "failure",
        host=host,
        user=auth["user"],
        src_ip=auth["ip"],
        src_port=int(auth["port"]),
        dst_ip=dst_ip,
        dst_port=22,
        protocol="tcp",
        raw=line,
        extra={
            "auth_method": auth["method"],
            "invalid_user": bool(auth["invalid"]),
            "pid": int(m["pid"]),
        },
    )
