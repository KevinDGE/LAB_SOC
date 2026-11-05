"""Parser de eventos de Windows exportados como JSON (un evento por línea).

Formato similar al que produce ``Get-WinEvent | ConvertTo-Json`` o Winlogbeat::

    {"TimeCreated": "2026-10-14T11:02:10Z", "EventID": 4625, "Channel": "Security",
     "Computer": "EXCH01.corp.local", "EventData": {"TargetUserName": "r.medina",
     "IpAddress": "198.51.100.66", "IpPort": "50211", "LogonType": 8,
     "Status": "0xC000006D", "SubStatus": "0xC000006A"}}

Eventos soportados: 4624 (logon correcto), 4625 (logon fallido) y
7045 (servicio instalado, canal System).
"""

from __future__ import annotations

import json

from soc_lab.schema import Event, parse_ts
from soc_lab.simulator.topology import asset_by_name

LOGON_EVENTS = {
    4624: ("logon_success", "success"),
    4625: ("logon_failure", "failure"),
}


def _host_ip(host: str) -> str | None:
    try:
        return asset_by_name(host).ip
    except KeyError:
        return None


def _clean(value: str | None) -> str | None:
    return None if value in (None, "", "-") else value


def parse_line(line: str) -> Event | None:
    line = line.strip()
    if not line:
        return None
    record = json.loads(line)
    event_id = int(record["EventID"])
    host = record["Computer"].split(".")[0]
    data = record.get("EventData", {})
    ts = parse_ts(record["TimeCreated"])

    if event_id in LOGON_EVENTS:
        action, outcome = LOGON_EVENTS[event_id]
        port = _clean(data.get("IpPort"))
        extra = {"workstation": _clean(data.get("WorkstationName"))}
        if event_id == 4625:
            extra["status"] = data.get("Status")
            extra["sub_status"] = data.get("SubStatus")
        return Event(
            timestamp=ts,
            source="windows",
            event_code=str(event_id),
            category="authentication",
            action=action,
            outcome=outcome,
            host=host,
            user=data.get("TargetUserName"),
            src_ip=_clean(data.get("IpAddress")),
            src_port=int(port) if port else None,
            dst_ip=_host_ip(host),
            logon_type=int(data["LogonType"]),
            raw=line,
            extra=extra,
        )

    if event_id == 7045:
        return Event(
            timestamp=ts,
            source="windows",
            event_code="7045",
            category="service",
            action="service_install",
            outcome="success",
            host=host,
            user=data.get("AccountName"),
            dst_ip=_host_ip(host),
            service_name=data.get("ServiceName"),
            raw=line,
            extra={
                "image_path": data.get("ImagePath", ""),
                "start_type": data.get("StartType", ""),
            },
        )
    return None
