"""Escenarios de ataque simulados (uno por caso de investigación).

Cada escenario escribe registros crudos en ``RawLogs`` y devuelve metadatos de
*ground truth* (atacante, ventana temporal, técnicas y reglas que deberían
dispararse). Esos metadatos permiten medir la cobertura de detección en las
pruebas sin acoplar las pruebas al detalle de cada log.

Todas las IPs externas pertenecen a rangos de documentación (RFC 5737).
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from soc_lab.schema import format_ts
from soc_lab.simulator import topology as topo
from soc_lab.simulator.background import COMMON_SCAN_PORTS
from soc_lab.simulator.writer import RawLogs

TOP_PORTS = sorted(set(COMMON_SCAN_PORTS + [
    7, 9, 13, 37, 79, 81, 88, 102, 113, 119, 123, 161, 179, 199, 444, 513, 514,
    515, 543, 544, 548, 554, 631, 873, 902, 990, 1025, 1080, 1194, 1723, 1883,
    2000, 2082, 2083, 2181, 2375, 3000, 3128, 4444, 5000, 5060, 5601, 5672, 6379,
    6443, 7001, 8000, 8008, 8081, 8088, 8888, 9000, 9090, 9200, 9443, 10000,
    11211, 27017,
]))


@dataclass
class Scenario:
    scenario_id: str
    title: str
    attacker: list[str]
    start: datetime
    end: datetime
    techniques: list[str]
    expected_rules: list[str]
    assets: list[str] = field(default_factory=list)  # equipos/cuentas afectados
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["start"], data["end"] = format_ts(self.start), format_ts(self.end)
        return data


def _t(day: datetime, hh: int, mm: int, ss: int = 0) -> datetime:
    return day + timedelta(hours=hh, minutes=mm, seconds=ss)


# --------------------------------------------------------------------------
# CASE-001: reconocimiento externo + fuerza bruta SSH con acceso exitoso
# --------------------------------------------------------------------------
def ssh_bruteforce(logs: RawLogs, rng: random.Random, day: datetime) -> Scenario:
    attacker = "203.0.113.77"
    web = topo.asset_by_name("srv-web-01")
    open_ports = {22, 80, 443}

    # 02:47 – escaneo de puertos TCP SYN contra el servidor web.
    ts = _t(day, 2, 47, 3)
    ports = TOP_PORTS[:]
    rng.shuffle(ports)
    for port in ports:
        ts += timedelta(milliseconds=rng.randint(150, 700))
        logs.fw(ts, attacker, rng.randint(40000, 40100), web.ip, port,
                allowed=port in open_ports, bytes_=60 if port in open_ports else 0,
                rule="allow-dmz-web" if port in (80, 443) else ("allow-dmz-ssh" if port == 22 else None))

    # 03:05 – diccionario SSH contra 6 usuarios.
    users = ["root", "admin", "ubuntu", "test", "deploy", "oracle"]
    ts = _t(day, 3, 5, 0)
    for _ in range(214):
        ts += timedelta(seconds=rng.randint(2, 6))
        user = rng.choice(users)
        sport = rng.randint(32768, 60999)
        logs.fw(ts, attacker, sport, web.ip, 22, bytes_=rng.randint(1500, 4000), rule="allow-dmz-ssh")
        logs.ssh_auth(ts, web.hostname, user, attacker, sport, False,
                      invalid_user=user in ("admin", "test", "oracle"))

    # 03:21:14 – la contraseña débil de "deploy" cae.
    success_ts = _t(day, 3, 21, 14)
    logs.fw(success_ts, attacker, 40022, web.ip, 22, bytes_=48_000, rule="allow-dmz-ssh")
    logs.ssh_auth(success_ts, web.hostname, "deploy", attacker, 40022, True)

    # 03:24 – descarga de herramientas desde un servidor de staging.
    logs.fw(_t(day, 3, 24, 40), web.ip, 51522, "198.51.100.23", 443,
            bytes_=2_418_331, rule="allow-dmz-out")
    logs.fw(_t(day, 3, 31, 2), web.ip, 51588, "198.51.100.23", 443,
            bytes_=88_120, rule="allow-dmz-out")

    return Scenario(
        "CASE-001", "Fuerza bruta SSH con acceso exitoso a srv-web-01",
        [attacker, "198.51.100.23"], _t(day, 2, 47), _t(day, 3, 32),
        ["T1046", "T1110.001", "T1078", "T1105"],
        ["SOC-005", "SOC-001", "SOC-004"],
        ["srv-web-01", "deploy"],
        ["El usuario deploy admitía autenticación por contraseña (debería ser solo clave)."],
    )


# --------------------------------------------------------------------------
# CASE-002: password spraying contra OWA (EXCH01)
# --------------------------------------------------------------------------
def password_spray(logs: RawLogs, rng: random.Random, day: datetime) -> Scenario:
    attacker = "198.51.100.66"
    mail = topo.asset_by_name("EXCH01")
    victims = {"r.medina", "e.vega"}
    accounts = topo.employee_accounts()
    rng.shuffle(accounts)
    # Garantiza que los aciertos ocurran tras varios fallos (realista y
    # necesario para la correlación fallo→éxito).
    for name, pos in (("r.medina", 14), ("e.vega", 29)):
        accounts.remove(name)
        accounts.insert(pos, name)

    ts = _t(day, 11, 2, 10)
    for account in accounts:
        ts += timedelta(seconds=rng.randint(40, 75))
        sport = rng.randint(49152, 65535)
        logs.fw(ts, attacker, sport, mail.ip, 443, bytes_=rng.randint(3000, 7000), rule="allow-dmz-owa")
        logs.win_logon(ts, mail.hostname, account, 8, attacker, sport, success=account in victims)
    end = ts

    # Acceso posterior al buzón de r.medina.
    ts = _t(day, 11, 58, 30)
    for _ in range(4):
        ts += timedelta(minutes=rng.randint(3, 9))
        sport = rng.randint(49152, 65535)
        logs.fw(ts, attacker, sport, mail.ip, 443, bytes_=rng.randint(200_000, 3_000_000), rule="allow-dmz-owa")
        logs.win_logon(ts, mail.hostname, "r.medina", 8, attacker, sport)

    return Scenario(
        "CASE-002", "Password spraying contra OWA con dos cuentas comprometidas",
        [attacker], _t(day, 11, 2), max(end, ts) + timedelta(minutes=1),
        ["T1110.003", "T1078"],
        ["SOC-003", "SOC-004"],
        ["EXCH01", "r.medina", "e.vega"],
        ["Contraseña probada: patrón estacional (Primavera2026!)."],
    )


# --------------------------------------------------------------------------
# CASE-003: equipo interno comprometido → descubrimiento → movimiento lateral
# --------------------------------------------------------------------------
def lateral_movement(logs: RawLogs, rng: random.Random, day: datetime) -> Scenario:
    ws = topo.asset_by_name("WS-017")
    c2 = "192.0.2.150"
    admin = "adm.m.fuentes"

    # 13:38 – primer contacto con C2 y beaconing cada ~60 s (brecha de detección).
    ts = _t(day, 13, 38, 12)
    while ts < _t(day, 15, 30):
        logs.fw(ts, ws.ip, rng.randint(49152, 65535), c2, 443,
                bytes_=rng.randint(900, 2600), rule="allow-web-out")
        ts += timedelta(seconds=60 + rng.randint(-6, 6))

    # 14:10 – barrido SMB del segmento de servidores.
    ts = _t(day, 14, 10, 5)
    live = {a.ip for a in topo.all_assets()}
    for last_octet in range(1, 61):
        ip = f"10.10.1.{last_octet}"
        ts += timedelta(milliseconds=rng.randint(300, 1500))
        logs.fw(ts, ws.ip, rng.randint(49152, 65535), ip, 445,
                bytes_=180 if ip in live else 0, rule="allow-internal")

    # 14:14 – escaneo de puertos dirigido a DB01.
    db = topo.asset_by_name("DB01")
    ts = _t(day, 14, 14, 30)
    for port in rng.sample(TOP_PORTS, 42):
        ts += timedelta(milliseconds=rng.randint(400, 1400))
        allowed = port in (135, 445, 1433, 3389, 5985)
        logs.fw(ts, ws.ip, rng.randint(49152, 65535), db.ip, port, allowed=allowed,
                bytes_=60 if allowed else 0, rule="allow-internal" if allowed else None)

    # 14:31 – uso de credenciales del helpdesk robadas de memoria.
    hops = [(_t(day, 14, 31, 7), "FS01"), (_t(day, 14, 36, 40), "APP01"),
            (_t(day, 14, 40, 2), "DB01"), (_t(day, 14, 44, 18), "BACKUP01")]
    dc_ts = _t(day, 14, 33, 55)
    logs.fw(dc_ts, ws.ip, 50111, topo.asset_by_name("DC01").ip, 445, bytes_=900, rule="allow-ad")
    logs.win_logon(dc_ts, "DC01", admin, 3, ws.ip, 50111, success=False, workstation="WS-017",
                   status="0xC000015B", sub_status="0x0")
    for hop_ts, host in hops:
        sport = rng.randint(49152, 65535)
        target = topo.asset_by_name(host)
        logs.fw(hop_ts, ws.ip, sport, target.ip, 445, bytes_=rng.randint(40_000, 300_000), rule="allow-internal")
        logs.win_logon(hop_ts, host, admin, 3, ws.ip, sport, workstation="WS-017")

    # Ejecución remota de servicios (PsExec y un servicio con PowerShell).
    logs.win_service_install(_t(day, 14, 41, 9), "DB01", "PSEXESVC", r"%SystemRoot%\PSEXESVC.exe")
    logs.win_service_install(
        _t(day, 14, 45, 1), "BACKUP01", "WinSvcUpd",
        '%COMSPEC% /c powershell.exe -nop -w hidden -c "vssadmin list shadows"',
    )

    # 14:52 – sesión RDP desde la estación (no desde el jump host).
    sport = rng.randint(49152, 65535)
    rdp_ts = _t(day, 14, 52, 33)
    logs.fw(rdp_ts, ws.ip, sport, db.ip, 3389, bytes_=6_500_000, rule="allow-internal")
    logs.win_logon(rdp_ts, "DB01", admin, 10, ws.ip, sport, workstation="WS-017")

    # 15:05 – exfiltración desde DB01 al C2 (brecha de detección).
    ts = _t(day, 15, 5, 0)
    for _ in range(6):
        ts += timedelta(minutes=rng.randint(1, 3), seconds=rng.randint(0, 59))
        logs.fw(ts, db.ip, rng.randint(49152, 65535), c2, 443,
                bytes_=rng.randint(120_000_000, 160_000_000), rule="allow-web-out")

    return Scenario(
        "CASE-003", "Movimiento lateral desde WS-017 con credenciales de helpdesk",
        [ws.ip, c2], _t(day, 13, 38), _t(day, 15, 30),
        ["T1071.001", "T1046", "T1018", "T1078.002", "T1021.002", "T1569.002", "T1021.001", "T1041"],
        ["SOC-006", "SOC-005", "SOC-007", "SOC-008", "SOC-009"],
        ["WS-017", "FS01", "APP01", "DB01", "BACKUP01", admin],
        ["Las credenciales de adm.m.fuentes quedaron en memoria tras la sesión RDP de soporte de las 10:15."],
    )


ALL_SCENARIOS = [ssh_bruteforce, password_spray, lateral_movement]
