"""Topología ficticia de la organización "Acme Andina S.A." (dominio corp.local).

Las IPs externas usan exclusivamente rangos reservados para documentación
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), por lo que ningún
dato apunta a infraestructura real.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Asset:
    hostname: str
    ip: str
    role: str
    os: str
    criticality: str


SERVERS = [
    Asset("DC01", "10.10.1.10", "Controlador de dominio", "Windows Server 2022", "crítica"),
    Asset("FS01", "10.10.1.20", "Servidor de archivos", "Windows Server 2019", "alta"),
    Asset("APP01", "10.10.1.30", "Servidor de aplicaciones (ERP)", "Windows Server 2019", "alta"),
    Asset("DB01", "10.10.1.40", "Base de datos SQL Server", "Windows Server 2019", "crítica"),
    Asset("BACKUP01", "10.10.1.50", "Servidor de respaldos", "Windows Server 2019", "alta"),
    Asset("EXCH01", "10.10.2.20", "Correo / OWA (DMZ)", "Windows Server 2019", "alta"),
    Asset("srv-web-01", "10.10.2.10", "Servidor web público (DMZ)", "Ubuntu 22.04 LTS", "alta"),
]

SECURITY_TOOLS = [
    Asset("SCAN01", "10.10.5.5", "Escáner de vulnerabilidades autorizado", "Linux", "media"),
    Asset("JUMP01", "10.10.5.10", "Jump host de administración", "Windows Server 2022", "alta"),
]

FIREWALL = "fw01"

FIRST_NAMES = [
    "ana", "bruno", "carla", "diego", "elena", "felipe", "gabriela", "hector",
    "ines", "jorge", "karen", "luis", "maria", "nicolas", "olga", "pablo",
    "quique", "rosa", "sergio", "tatiana", "ulises", "valeria", "walter",
    "ximena", "yolanda", "zoe", "andres", "beatriz", "camilo", "daniela",
    "esteban", "fernanda", "gonzalo", "helena", "ivan", "julia", "kevin",
    "lucia", "martin", "natalia",
]
LAST_NAMES = [
    "martinez", "gomez", "rodriguez", "lopez", "perez", "sanchez", "ramirez",
    "torres", "flores", "rivera", "gutierrez", "morales", "ortiz", "castro",
    "vargas", "rojas", "herrera", "medina", "aguilar", "jimenez", "ruiz",
    "diaz", "mendoza", "silva", "cruz", "reyes", "garcia", "nunez", "romero",
    "suarez", "vega", "campos", "rios", "luna", "paredes", "salazar", "molina",
    "cabrera", "fuentes", "navarro",
]


def employee_accounts() -> list[str]:
    """40 cuentas de empleado con formato inicial.apellido."""
    return [f"{fn[0]}.{ln}" for fn, ln in zip(FIRST_NAMES, LAST_NAMES)]


def workstations() -> list[Asset]:
    return [
        Asset(f"WS-{i:03d}", f"10.10.20.{i}", "Estación de trabajo", "Windows 11", "media")
        for i in range(1, 41)
    ]


def all_assets() -> list[Asset]:
    return SERVERS + SECURITY_TOOLS + workstations()


def asset_by_name(hostname: str) -> Asset:
    for asset in all_assets():
        if asset.hostname == hostname:
            return asset
    raise KeyError(hostname)


def asset_by_ip(ip: str) -> Asset | None:
    for asset in all_assets():
        if asset.ip == ip:
            return asset
    return None


# Cuentas privilegiadas y de servicio (no son empleados de negocio).
ADMIN_ACCOUNTS = ["adm.l.cabrera", "adm.m.fuentes"]
SERVICE_ACCOUNTS = ["svc_backup", "svc_sql", "svc_erp"]
AUTHORIZED_SCANNERS = ["10.10.5.5"]  # SCAN01
ADMIN_SOURCES = ["10.10.5.10"]  # JUMP01

INTERNAL_CIDR = "10.10.0.0/16"
DOCUMENTATION_CIDRS = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]


def workstation_of(account: str) -> Asset:
    """Cada empleado tiene asignada una estación fija (WS-001 → primera cuenta)."""
    index = employee_accounts().index(account)
    return workstations()[index]
