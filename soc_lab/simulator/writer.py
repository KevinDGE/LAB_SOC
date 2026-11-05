"""Construcción de registros crudos en el formato nativo de cada fuente.

El generador nunca escribe eventos normalizados directamente: produce líneas
tal como las emitiría cada producto (sshd, Windows, firewall) y luego los
parsers las normalizan. Así el pipeline completo (crudo → normalizado →
detección) queda ejercitado igual que en un SIEM real.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from soc_lab.schema import format_ts

DOMAIN = "corp.local"


@dataclass
class RawLogs:
    sshd: list[tuple[datetime, str]] = field(default_factory=list)
    windows: list[tuple[datetime, dict]] = field(default_factory=list)
    firewall: list[tuple[datetime, str]] = field(default_factory=list)
    _pid: int = 2000

    # ------------------------------------------------------------------ sshd
    def ssh_auth(
        self,
        ts: datetime,
        host: str,
        user: str,
        src_ip: str,
        src_port: int,
        success: bool,
        method: str = "password",
        invalid_user: bool = False,
    ) -> None:
        self._pid += 1
        result = "Accepted" if success else "Failed"
        invalid = "invalid user " if invalid_user and not success else ""
        line = (
            f"{format_ts(ts)} {host} sshd[{self._pid}]: {result} {method} for "
            f"{invalid}{user} from {src_ip} port {src_port} ssh2"
        )
        self.sshd.append((ts, line))

    # --------------------------------------------------------------- windows
    def win_logon(
        self,
        ts: datetime,
        host: str,
        user: str,
        logon_type: int,
        src_ip: str | None,
        src_port: int | None = None,
        success: bool = True,
        workstation: str | None = None,
        status: str = "0xC000006D",
        sub_status: str = "0xC000006A",
    ) -> None:
        data = {
            "TargetUserName": user,
            "TargetDomainName": "CORP",
            "LogonType": logon_type,
            "IpAddress": src_ip or "-",
            "IpPort": str(src_port) if src_port else "-",
            "WorkstationName": workstation or "-",
            "AuthenticationPackageName": "NTLM" if logon_type in (3, 8) else "Negotiate",
        }
        if not success:
            data["Status"] = status
            data["SubStatus"] = sub_status
        self.windows.append(
            (
                ts,
                {
                    "TimeCreated": format_ts(ts),
                    "EventID": 4624 if success else 4625,
                    "Channel": "Security",
                    "Provider": "Microsoft-Windows-Security-Auditing",
                    "Computer": f"{host}.{DOMAIN}",
                    "EventData": data,
                },
            )
        )

    def win_service_install(
        self, ts: datetime, host: str, service_name: str, image_path: str,
        account: str = "LocalSystem", start_type: str = "demand start",
    ) -> None:
        self.windows.append(
            (
                ts,
                {
                    "TimeCreated": format_ts(ts),
                    "EventID": 7045,
                    "Channel": "System",
                    "Provider": "Service Control Manager",
                    "Computer": f"{host}.{DOMAIN}",
                    "EventData": {
                        "ServiceName": service_name,
                        "ImagePath": image_path,
                        "ServiceType": "user mode service",
                        "StartType": start_type,
                        "AccountName": account,
                    },
                },
            )
        )

    # -------------------------------------------------------------- firewall
    def fw(
        self,
        ts: datetime,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        allowed: bool = True,
        proto: str = "tcp",
        bytes_: int = 0,
        rule: str | None = None,
    ) -> None:
        action = "allow" if allowed else "deny"
        rule = rule or ("allow-policy" if allowed else "default-deny")
        line = (
            f"{format_ts(ts)} fw01 action={action} proto={proto} src={src_ip} "
            f"spt={src_port} dst={dst_ip} dpt={dst_port} bytes={bytes_} rule={rule}"
        )
        self.firewall.append((ts, line))

    # ----------------------------------------------------------------- write
    def write(self, raw_dir: Path) -> dict[str, int]:
        raw_dir.mkdir(parents=True, exist_ok=True)
        counts: dict[str, int] = {}

        sshd = sorted(self.sshd)
        (raw_dir / "sshd.log").write_text("".join(f"{l}\n" for _, l in sshd), encoding="utf-8")
        counts["sshd.log"] = len(sshd)

        # EventRecordID incremental por equipo, como en un visor de eventos real.
        record_ids: dict[str, int] = defaultdict(lambda: 10_000)
        lines = []
        for _, rec in sorted(self.windows, key=lambda r: (r[0], json.dumps(r[1], sort_keys=True))):
            record_ids[rec["Computer"]] += 1
            rec = {**rec, "EventRecordID": record_ids[rec["Computer"]]}
            lines.append(json.dumps(rec, ensure_ascii=False, sort_keys=True))
        (raw_dir / "windows.jsonl").write_text("".join(f"{l}\n" for l in lines), encoding="utf-8")
        counts["windows.jsonl"] = len(lines)

        fw = sorted(self.firewall)
        (raw_dir / "firewall.log").write_text("".join(f"{l}\n" for _, l in fw), encoding="utf-8")
        counts["firewall.log"] = len(fw)
        return counts
