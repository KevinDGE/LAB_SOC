"""Tráfico benigno de fondo para un día laboral en Acme Andina S.A.

Incluye ruido realista que un analista ve a diario y que las reglas deben
tolerar sin generar alertas:

* inicios de sesión de empleados (con errores de tipeo ocasionales),
* acceso a recursos compartidos y al ERP,
* administración legítima desde el jump host (RDP, SSH con clave pública),
* tareas de cuentas de servicio y respaldos nocturnos,
* navegación web saliente y clientes de Internet hacia la DMZ,
* "radiación de fondo" de Internet (intentos SSH sueltos, puertos bloqueados),
* el escaneo de vulnerabilidades autorizado de SCAN01 (debe quedar suprimido),
* un falso positivo deliberado: ``svc_backup`` con contraseña expirada.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from soc_lab.simulator import topology as topo
from soc_lab.simulator.writer import RawLogs

# IPs reservadas para los escenarios de ataque; el ruido nunca las usa.
RESERVED_EXTERNAL = {"203.0.113.77", "198.51.100.66", "192.0.2.150", "198.51.100.23"}

COMMON_SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 8080, 8443,
]


class Background:
    def __init__(self, logs: RawLogs, rng: random.Random, day: datetime):
        self.logs = logs
        self.rng = rng
        self.day = day

    # -------------------------------------------------------------- helpers
    def at(self, hour: float, jitter_min: float = 0) -> datetime:
        offset = hour * 3600 + self.rng.uniform(-jitter_min, jitter_min) * 60
        offset = min(max(offset, 0), 86_399)
        return self.day + timedelta(seconds=int(offset))

    def eph(self) -> int:
        return self.rng.randint(49152, 65535)

    def external_ip(self) -> str:
        while True:
            prefix = self.rng.choice(["192.0.2", "198.51.100", "203.0.113"])
            ip = f"{prefix}.{self.rng.randint(1, 254)}"
            if ip not in RESERVED_EXTERNAL:
                return ip

    # ----------------------------------------------------------------- run
    def generate(self) -> None:
        self.employees()
        self.admins()
        self.service_accounts()
        self.dmz_inbound()
        self.internet_noise()
        self.authorized_scan()
        self.expired_service_password()
        self.benign_service_installs()

    def employees(self) -> None:
        dc, fs, app = (topo.asset_by_name(n) for n in ("DC01", "FS01", "APP01"))
        for account in topo.employee_accounts():
            ws = topo.workstation_of(account)
            start = self.at(self.rng.uniform(7.5, 9.5))
            end_hour = self.rng.uniform(17.0, 19.0)

            # Errores de tipeo ocasionales antes del logon interactivo.
            if self.rng.random() < 0.15:
                for i in range(self.rng.randint(1, 2)):
                    self.logs.win_logon(start - timedelta(seconds=20 - 8 * i), ws.hostname, account,
                                        2, "127.0.0.1", success=False, workstation=ws.hostname)
            self.logs.win_logon(start, ws.hostname, account, 2, "127.0.0.1", workstation=ws.hostname)

            # Autenticación y DNS contra el DC al iniciar sesión.
            for port in (88, 389, 53):
                self.logs.fw(start + timedelta(seconds=2), ws.ip, self.eph(), dc.ip, port,
                             proto="udp" if port == 53 else "tcp", bytes_=self.rng.randint(300, 4000),
                             rule="allow-ad")

            # Recursos compartidos (FS01) y ERP (APP01) durante la jornada.
            for target, port, n in ((fs, 445, self.rng.randint(3, 8)), (app, 443, self.rng.randint(1, 4))):
                for _ in range(n):
                    ts = self.at(self.rng.uniform((start - self.day).seconds / 3600, end_hour))
                    sport = self.eph()
                    if self.rng.random() < 0.05:
                        self.logs.win_logon(ts - timedelta(seconds=5), target.hostname, account, 3,
                                            ws.ip, sport, success=False, workstation=ws.hostname)
                    self.logs.win_logon(ts, target.hostname, account, 3, ws.ip, sport,
                                        workstation=ws.hostname)
                    self.logs.fw(ts, ws.ip, sport, target.ip, port,
                                 bytes_=self.rng.randint(5_000, 2_000_000), rule="allow-internal")

            # Navegación web saliente.
            for _ in range(self.rng.randint(15, 35)):
                ts = self.at(self.rng.uniform(8, end_hour))
                self.logs.fw(ts, ws.ip, self.eph(), self.external_ip(), self.rng.choice([443, 443, 443, 80]),
                             bytes_=self.rng.randint(2_000, 900_000), rule="allow-web-out")

    def admins(self) -> None:
        jump = topo.asset_by_name("JUMP01")
        plan = {
            "adm.l.cabrera": [(9.1, "DC01"), (9.6, "FS01"), (16.2, "BACKUP01")],
            # El helpdesk atiende WS-017 por RDP a las 10:15: sus credenciales
            # quedan en memoria del equipo (relevante en CASE-003).
            "adm.m.fuentes": [(10.25, "WS-017"), (11.5, "APP01")],
        }
        for admin, sessions in plan.items():
            self.logs.win_logon(self.at(8.9, 5), "JUMP01", admin, 2, "127.0.0.1", workstation="JUMP01")
            for hour, host in sessions:
                target = topo.asset_by_name(host)
                ts = self.at(hour, 3)
                sport = self.eph()
                self.logs.fw(ts, jump.ip, sport, target.ip, 3389, bytes_=self.rng.randint(1_000_000, 9_000_000),
                             rule="allow-admin-rdp")
                self.logs.win_logon(ts, host, admin, 10, jump.ip, sport, workstation="JUMP01")

        # Despliegues en el servidor web con clave pública desde el jump host.
        web = topo.asset_by_name("srv-web-01")
        for hour in (10.0, 15.0, 16.5):
            ts = self.at(hour, 10)
            sport = self.rng.randint(32768, 60999)
            self.logs.fw(ts, jump.ip, sport, web.ip, 22, bytes_=self.rng.randint(20_000, 300_000),
                         rule="allow-admin-ssh")
            self.logs.ssh_auth(ts, web.hostname, "deploy", jump.ip, sport, True, method="publickey")

    def service_accounts(self) -> None:
        backup, fs, db, app = (topo.asset_by_name(n) for n in ("BACKUP01", "FS01", "DB01", "APP01"))
        # Respaldo nocturno.
        for target, port in ((fs, 445), (db, 1433)):
            ts = self.at(1.0, 15)
            sport = self.eph()
            self.logs.win_logon(ts, target.hostname, "svc_backup", 3, backup.ip, sport, workstation="BACKUP01")
            self.logs.fw(ts, backup.ip, sport, target.ip, port, bytes_=self.rng.randint(400_000_000, 900_000_000),
                         rule="allow-backup")
        # SQL Server arranca como servicio.
        self.logs.win_logon(self.at(0.05), "DB01", "svc_sql", 5, "-")
        # El ERP consulta la base de datos cada hora.
        for hour in range(24):
            ts = self.at(hour + 0.1, 2)
            sport = self.eph()
            self.logs.win_logon(ts, "DB01", "svc_erp", 3, app.ip, sport, workstation="APP01")
            self.logs.fw(ts, app.ip, sport, db.ip, 1433, bytes_=self.rng.randint(10_000, 400_000),
                         rule="allow-erp-db")

    def dmz_inbound(self) -> None:
        web, mail = topo.asset_by_name("srv-web-01"), topo.asset_by_name("EXCH01")
        clients = [self.external_ip() for _ in range(150)]
        for _ in range(650):
            hour = self.rng.triangular(0, 24, 14)
            self.logs.fw(self.at(hour), self.rng.choice(clients), self.eph(), web.ip,
                         self.rng.choice([443, 443, 443, 80]), bytes_=self.rng.randint(800, 250_000),
                         rule="allow-dmz-web")
        for _ in range(220):
            hour = self.rng.triangular(6, 22, 12)
            self.logs.fw(self.at(hour), self.rng.choice(clients), self.eph(), mail.ip, 443,
                         bytes_=self.rng.randint(1_000, 80_000), rule="allow-dmz-owa")

    def internet_noise(self) -> None:
        """Bots de Internet: pocos intentos por IP, por debajo de los umbrales."""
        web, mail = topo.asset_by_name("srv-web-01"), topo.asset_by_name("EXCH01")
        users = ["root", "admin", "test", "oracle", "ubuntu", "user", "pi", "git"]
        for _ in range(28):
            ip = self.external_ip()
            ts = self.at(self.rng.uniform(0, 23.5))  # margen para que la ráfaga no cruce de día
            for _ in range(self.rng.randint(1, 4)):
                ts += timedelta(seconds=self.rng.randint(2, 40))
                user = self.rng.choice(users)
                sport = self.rng.randint(32768, 60999)
                self.logs.fw(ts, ip, sport, web.ip, 22, bytes_=self.rng.randint(1_000, 5_000),
                             rule="allow-dmz-ssh")
                self.logs.ssh_auth(ts, web.hostname, user, ip, sport, False,
                                   invalid_user=user not in ("root", "ubuntu"))
        for _ in range(70):
            ip = self.external_ip()
            ts = self.at(self.rng.uniform(0, 23.5))
            for port in self.rng.sample(COMMON_SCAN_PORTS, self.rng.randint(1, 5)):
                ts += timedelta(seconds=self.rng.randint(1, 30))
                if port in (22, 80, 443):
                    continue
                self.logs.fw(ts, ip, self.eph(), self.rng.choice([web.ip, mail.ip]), port, allowed=False)

    def authorized_scan(self) -> None:
        """Escaneo semanal autorizado (ventana de cambio CHG-2291)."""
        scanner = topo.asset_by_name("SCAN01")
        ts = self.at(2.0)
        for server in topo.SERVERS:
            for port in COMMON_SCAN_PORTS:
                ts += timedelta(milliseconds=self.rng.randint(200, 900))
                self.logs.fw(ts, scanner.ip, self.eph(), server.ip, port,
                             allowed=True, bytes_=self.rng.randint(0, 600), rule="allow-vuln-scanner")

    def expired_service_password(self) -> None:
        """Falso positivo de manual: tarea programada con contraseña expirada."""
        backup = topo.asset_by_name("BACKUP01")
        ts = self.at(20.0)
        for _ in range(36):
            ts += timedelta(seconds=self.rng.randint(35, 45))
            self.logs.win_logon(ts, "FS01", "svc_backup", 3, backup.ip, self.eph(), success=False,
                                workstation="BACKUP01", sub_status="0xC0000071")

    def benign_service_installs(self) -> None:
        self.logs.win_service_install(self.at(21.0), "APP01", "AcmeERPUpdater",
                                      r'"C:\Program Files\Acme\ERP\updater.exe" --service',
                                      start_type="auto start")
        self.logs.win_service_install(self.at(12.3), "WS-005", "edgeupdate",
                                      r'"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc',
                                      start_type="auto start")
