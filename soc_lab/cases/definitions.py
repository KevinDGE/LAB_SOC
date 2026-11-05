"""Definición de los casos de investigación.

Cada caso declara:

* qué alertas agrupa (ventana temporal + entidades pivote),
* qué eventos de contexto entran en la línea de tiempo (filtros con la misma
  sintaxis que las reglas; ``aggregate`` resume muchos eventos en una entrada),
* qué líneas crudas se citan como evidencia en el reporte,
* la narrativa del analista (resumen, análisis, respuesta, lecciones).

Las cifras (conteos, horas, IoCs, mapeo ATT&CK) no se escriben a mano: el
builder las calcula a partir de los datos, por lo que el reporte siempre es
coherente con lo que muestra el dashboard.
"""

from __future__ import annotations

CASES = [
    # ------------------------------------------------------------------
    {
        "case_id": "CASE-001",
        "title": "Fuerza bruta SSH con acceso exitoso a srv-web-01",
        "severity": "critical",
        "status": "Cerrado",
        "classification": "Verdadero positivo — compromiso de cuenta",
        "window": ["2026-10-14T02:30:00Z", "2026-10-14T04:00:00Z"],
        "pivots": ["203.0.113.77", "srv-web-01", "deploy"],
        "context": [
            {
                "title": "Puertos expuestos confirmados por el atacante",
                "filter": {"source": "firewall", "src_ip": "203.0.113.77", "outcome": "allowed",
                           "dst_port": {"in": [80, 443]}},
                "aggregate": True,
                "technique": "T1046",
                "detail": "El escaneo obtuvo respuesta en los puertos {dst_ports} de {dst_ips} (además de 22/SSH).",
            },
            {
                "title": "Ataque de diccionario SSH",
                "filter": {"source": "sshd", "src_ip": "203.0.113.77", "outcome": "failure"},
                "aggregate": True,
                "technique": "T1110.001",
                "detail": "{count} contraseñas fallidas entre {first} y {last} contra los usuarios {users}.",
            },
            {
                "title": "Acceso SSH exitoso con contraseña",
                "filter": {"source": "sshd", "src_ip": "203.0.113.77", "outcome": "success"},
                "technique": "T1078",
                "detail": "{user} autenticado por {extra.auth_method} desde {src_ip}:{src_port}. "
                          "Esta cuenta solo usa clave pública desde JUMP01 en su actividad normal.",
                "key": True,
            },
            {
                "title": "Descarga de herramientas desde infraestructura externa",
                "filter": {"source": "firewall", "src_ip": "10.10.2.10", "dst_ip": "198.51.100.23"},
                "technique": "T1105",
                "detail": "srv-web-01 → {dst_ip}:{dst_port} ({mb} MB).",
                "key": True,
            },
        ],
        "evidence_samples": [
            {"filter": {"source": "firewall", "src_ip": "203.0.113.77", "outcome": "denied"}, "limit": 2},
            {"filter": {"source": "sshd", "src_ip": "203.0.113.77", "outcome": "failure"}, "limit": 3},
            {"filter": {"source": "sshd", "src_ip": "203.0.113.77", "outcome": "success"}, "limit": 1},
            {"filter": {"source": "firewall", "dst_ip": "198.51.100.23"}, "limit": 2},
        ],
        "extra_techniques": [{"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"}],
        "summary": (
            "Una IP externa (203.0.113.77) escaneó el servidor web público srv-web-01, identificó SSH "
            "expuesto a Internet y lanzó un ataque de diccionario contra seis usuarios. Tras unos 15 "
            "minutos obtuvo acceso con la cuenta de despliegue «deploy», que conservaba autenticación "
            "por contraseña y una contraseña débil. A los tres minutos el servidor descargó ~2,4 MB desde "
            "un host externo, compatible con la transferencia de herramientas del atacante."
        ),
        "analysis": [
            "**Reconocimiento.** El firewall registra conexiones a decenas de puertos distintos de "
            "10.10.2.10 en menos de un minuto desde 203.0.113.77, con puertos de origen casi constantes "
            "(40000–40100): patrón de un escáner SYN automatizado. Solo respondieron 22, 80 y 443.",
            "**Acceso a credenciales.** SOC-001 se disparó al décimo fallo. El diccionario combinó "
            "usuarios inexistentes (admin, test, oracle → `invalid user`) con cuentas reales (root, "
            "ubuntu, deploy), lo que sugiere una lista genérica y no reconocimiento previo de la "
            "organización.",
            "**Compromiso.** SOC-004 correlacionó los fallos con el `Accepted password for deploy` "
            "desde la misma IP. La línea base del día muestra que deploy solo se autentica con "
            "`publickey` desde JUMP01 (10.10.5.10); un acceso por contraseña desde Internet es anómalo "
            "por sí mismo.",
            "**Post-explotación.** La conexión saliente de srv-web-01 a 198.51.100.23:443 con 2,4 MB "
            "de transferencia ocurre 3 minutos después del acceso. No existe regla para este patrón "
            "(brecha de detección registrada abajo).",
        ],
        "scope": {
            "hosts": ["srv-web-01 (10.10.2.10) — servidor web público, DMZ"],
            "accounts": ["deploy (cuenta local de despliegue)"],
            "not_affected": "No se observa movimiento desde srv-web-01 hacia la red interna (10.10.1.0/24) "
                            "en los registros del firewall.",
        },
        "response": {
            "Contención": [
                "Bloquear 203.0.113.77 y 198.51.100.23 en el firewall perimetral.",
                "Aislar srv-web-01 de la DMZ y cerrar sesiones activas de deploy.",
            ],
            "Erradicación": [
                "Rotar la contraseña de deploy y deshabilitar `PasswordAuthentication` en sshd_config.",
                "Revisar `~deploy/.ssh/authorized_keys`, crontab y binarios descargados en /tmp.",
            ],
            "Recuperación": [
                "Reconstruir srv-web-01 desde imagen confiable y redeplegar la aplicación.",
                "Restringir 22/TCP a JUMP01 mediante regla de firewall.",
            ],
        },
        "lessons": [
            "SSH expuesto a Internet con autenticación por contraseña habilitada.",
            "Brecha de detección: no hay regla para conexiones salientes nuevas desde servidores de la DMZ "
            "tras un logon (propuesta: SOC-010 «Primera conexión saliente de servidor DMZ a destino no visto»).",
            "Añadir fail2ban/bloqueo automático tras SOC-001 para reducir la ventana de ataque.",
        ],
    },
    # ------------------------------------------------------------------
    {
        "case_id": "CASE-002",
        "title": "Password spraying contra OWA con dos cuentas comprometidas",
        "severity": "critical",
        "status": "Cerrado",
        "classification": "Verdadero positivo — compromiso de cuentas",
        "window": ["2026-10-14T10:45:00Z", "2026-10-14T12:45:00Z"],
        "pivots": ["198.51.100.66", "EXCH01"],
        "context": [
            {
                "title": "Comienza el spraying contra OWA",
                "filter": {"source": "windows", "src_ip": "198.51.100.66", "outcome": "failure"},
                "aggregate": True,
                "technique": "T1110.003",
                "detail": "{count} logons fallidos (LogonType 8) contra {distinct_users} cuentas distintas "
                          "entre {first} y {last}; una cuenta cada ~{avg_gap} s.",
            },
            {
                "title": "Credencial válida encontrada",
                "filter": {"source": "windows", "src_ip": "198.51.100.66", "outcome": "success"},
                "window": ["2026-10-14T11:00:00Z", "2026-10-14T11:45:00Z"],
                "technique": "T1078",
                "detail": "4624 LogonType 8 en EXCH01 para {user}: la contraseña probada es válida.",
                "key": True,
            },
            {
                "title": "Uso del buzón comprometido",
                "filter": {"source": "windows", "src_ip": "198.51.100.66", "outcome": "success"},
                "window": ["2026-10-14T11:45:00Z", "2026-10-14T12:45:00Z"],
                "aggregate": True,
                "technique": "T1078",
                "detail": "{count} sesiones OWA adicionales como {users} entre {first} y {last}.",
            },
        ],
        "evidence_samples": [
            {"filter": {"source": "windows", "src_ip": "198.51.100.66", "outcome": "failure"}, "limit": 2},
            {"filter": {"source": "windows", "src_ip": "198.51.100.66", "outcome": "success"}, "limit": 2},
        ],
        "extra_techniques": [],
        "summary": (
            "Entre las 11:03 y las 11:40 UTC la IP externa 198.51.100.66 probó una única contraseña "
            "contra las 40 cuentas de empleados a través de OWA (EXCH01), a razón de una cuenta por "
            "minuto para no activar los bloqueos por cuenta. Dos cuentas —r.medina y e.vega— usaban esa "
            "contraseña. El atacante volvió a acceder al buzón de r.medina cuatro veces más durante la "
            "siguiente hora."
        ),
        "analysis": [
            "**Patrón de spraying.** Ninguna cuenta supera un fallo, por lo que SOC-002 (fallos por cuenta) "
            "no se dispara; sí lo hace SOC-003 al contar usuarios distintos por origen. Este es el motivo "
            "de tener ambas reglas: cubren el mismo objetivo (T1110) desde ejes distintos.",
            "**Códigos de estado.** Todos los 4625 tienen `SubStatus 0xC000006A` (contraseña incorrecta), "
            "no `0xC0000064` (usuario inexistente): el atacante conocía la nomenclatura `inicial.apellido`, "
            "probablemente por OSINT (LinkedIn, firmas de correo).",
            "**Compromiso.** SOC-004 correlaciona los fallos con los logons exitosos desde la misma IP y "
            "agrupa en una sola alerta los accesos posteriores al buzón de r.medina, que indican uso activo "
            "de la cuenta (lectura de correo, posible preparación de BEC).",
        ],
        "scope": {
            "hosts": ["EXCH01 (10.10.2.20) — OWA expuesto en la DMZ"],
            "accounts": ["r.medina", "e.vega"],
            "not_affected": "Las otras 38 cuentas fallaron; no hay logons de r.medina ni e.vega desde orígenes "
                            "anómalos fuera de EXCH01.",
        },
        "response": {
            "Contención": [
                "Bloquear 198.51.100.66; forzar cierre de sesión y reseteo de r.medina y e.vega.",
                "Revisar reglas de reenvío y delegaciones creadas en ambos buzones.",
            ],
            "Erradicación": [
                "Buscar correos enviados por r.medina tras las 11:20 (phishing interno / BEC).",
                "Aplicar lista de contraseñas prohibidas (patrones estacionales como «Primavera2026!»).",
            ],
            "Recuperación": [
                "Habilitar MFA obligatorio en OWA y publicar OWA tras un proxy con protección de identidad.",
            ],
        },
        "lessons": [
            "OWA accesible desde Internet sin MFA.",
            "Política de contraseñas que admite patrones predecibles.",
            "Mejora de detección: alertar también cuando una IP externa nueva accede a un buzón tras una "
            "alerta SOC-003 aunque no supere el umbral de fallos.",
        ],
    },
    # ------------------------------------------------------------------
    {
        "case_id": "CASE-003",
        "title": "Movimiento lateral desde WS-017 con credenciales de helpdesk",
        "severity": "critical",
        "status": "Cerrado",
        "classification": "Verdadero positivo — intrusión interna con exfiltración",
        "window": ["2026-10-14T10:00:00Z", "2026-10-14T15:45:00Z"],
        "pivots": ["10.10.20.17", "WS-017", "adm.m.fuentes", "DB01", "BACKUP01"],
        "context": [
            {
                "title": "Sesión de soporte del helpdesk en WS-017",
                "filter": {"source": "windows", "host": "WS-017", "user": "adm.m.fuentes", "logon_type": 10},
                "technique": None,
                "detail": "RDP legítimo de {user} desde JUMP01 ({src_ip}). Las credenciales de la cuenta "
                          "privilegiada quedan en memoria (LSASS) del equipo.",
                "key": True,
            },
            {
                "title": "Beaconing HTTPS hacia 192.0.2.150",
                "filter": {"source": "firewall", "src_ip": "10.10.20.17", "dst_ip": "192.0.2.150"},
                "aggregate": True,
                "technique": "T1071.001",
                "detail": "{count} conexiones a {dst_ips}:443 entre {first} y {last}, cada ~{avg_gap} s y con "
                          "tamaño casi constante: patrón de implante C2. Sin alerta (brecha).",
            },
            {
                "title": "Intento de acceso a DC01 denegado",
                "filter": {"source": "windows", "host": "DC01", "user": "adm.m.fuentes", "outcome": "failure"},
                "technique": "T1078.002",
                "detail": "4625 con Status {extra.status}: la cuenta de helpdesk no tiene derecho de logon en el DC.",
                "key": True,
            },
            {
                "title": "Exfiltración desde DB01",
                "filter": {"source": "firewall", "src_ip": "10.10.1.40", "dst_ip": "192.0.2.150"},
                "aggregate": True,
                "technique": "T1041",
                "detail": "{count} conexiones salientes de DB01 a {dst_ips}:443 con {bytes_mb} MB en total "
                          "entre {first} y {last}. Sin alerta (brecha).",
            },
        ],
        "evidence_samples": [
            {"filter": {"source": "firewall", "src_ip": "10.10.20.17", "dst_ip": "192.0.2.150"}, "limit": 2},
            {"filter": {"source": "windows", "user": "adm.m.fuentes", "src_ip": "10.10.20.17"}, "limit": 3},
            {"filter": {"source": "windows", "event_code": "7045", "host": {"in": ["DB01", "BACKUP01"]},
                        "service_name": {"in": ["PSEXESVC", "WinSvcUpd"]}}, "limit": 2},
            {"filter": {"source": "firewall", "src_ip": "10.10.1.40", "dst_ip": "192.0.2.150"}, "limit": 2},
        ],
        "extra_techniques": [
            {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
            {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access"},
            {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
        ],
        "summary": (
            "La estación WS-017 (usuario q.herrera) comenzó a comunicarse con 192.0.2.150 cada minuto a "
            "partir de las 13:38 UTC. Desde ese equipo se barrió la subred de servidores por SMB, se escaneó "
            "DB01 y, con las credenciales de la cuenta de helpdesk adm.m.fuentes —que había iniciado sesión "
            "en WS-017 por soporte esa mañana—, el atacante se movió a FS01, APP01, DB01 y BACKUP01, ejecutó "
            "servicios remotos (PsExec y un servicio con PowerShell) y abrió una sesión RDP en DB01. Entre las "
            "15:06 y las 15:20 DB01 envió ~880 MB a 192.0.2.150."
        ),
        "analysis": [
            "**Vector inicial.** No es observable con las fuentes disponibles (no hay telemetría de correo ni "
            "EDR). El primer indicio es la conexión de WS-017 a 192.0.2.150; la regularidad de ~60 s sugiere un "
            "implante C2. El análisis del equipo debe confirmar el vector (phishing es la hipótesis principal).",
            "**Descubrimiento.** SOC-006 detecta el barrido SMB de 60 IPs en menos de un minuto y SOC-005 el "
            "escaneo de puertos de DB01; la severidad de SOC-005 sube a *alta* por tratarse de un origen interno.",
            "**Acceso a credenciales.** adm.m.fuentes atendió WS-017 por RDP a las 10:15 desde JUMP01 "
            "(legítimo). Que esa misma cuenta inicie sesión desde 10.10.20.17 —y no desde JUMP01— cuatro horas "
            "después indica robo de credenciales de memoria (T1003.001, inferido: sin EDR no hay evidencia directa).",
            "**Movimiento lateral y ejecución.** SOC-007 agrupa los logons de red a 4 servidores en 13 minutos; "
            "SOC-008 marca la instalación de PSEXESVC en DB01 y de un servicio que ejecuta "
            "`vssadmin list shadows` en BACKUP01 (reconocimiento de copias de sombra, frecuente antes de "
            "ransomware); SOC-009 detecta RDP a DB01 desde una estación. El fallo en DC01 (0xC000015B) muestra "
            "que la cuenta no tenía privilegios de dominio: el segmentado de privilegios limitó el alcance.",
            "**Exfiltración.** Seis conexiones de DB01 al mismo C2 suman ~880 MB. Ninguna regla actual mide "
            "volumen saliente; se identificó revisando el firewall a partir de la IP del C2.",
        ],
        "scope": {
            "hosts": ["WS-017 (10.10.20.17) — paciente cero", "FS01", "APP01", "DB01 (exfiltración)",
                      "BACKUP01 (ejecución remota)"],
            "accounts": ["q.herrera (usuario de WS-017)", "adm.m.fuentes (helpdesk, credenciales robadas)"],
            "not_affected": "DC01 rechazó el logon; no hay evidencia de compromiso del dominio.",
        },
        "response": {
            "Contención": [
                "Aislar WS-017, DB01 y BACKUP01 de la red; bloquear 192.0.2.150 en el perímetro y en DNS.",
                "Deshabilitar adm.m.fuentes y resetear q.herrera; invalidar tickets Kerberos (klist purge / krbtgt si aplica).",
            ],
            "Erradicación": [
                "Eliminar los servicios PSEXESVC y WinSvcUpd; adquirir memoria y disco de WS-017 para análisis forense.",
                "Buscar el hash del implante y conexiones a 192.0.2.150 en el resto de estaciones.",
            ],
            "Recuperación": [
                "Reinstalar WS-017; validar integridad de los respaldos en BACKUP01 antes de cualquier restauración.",
                "Notificar a legal/privacidad por la posible exfiltración de la base de datos (DB01).",
            ],
        },
        "lessons": [
            "Las cuentas privilegiadas no deben iniciar sesión interactiva en estaciones de usuario: usar LAPS, "
            "Remote Credential Guard o RDP en modo Restricted Admin para soporte.",
            "Brecha de detección: beaconing periódico (propuesta: SOC-011 sobre regularidad de conexiones salientes).",
            "Brecha de detección: volumen saliente anómalo desde servidores (propuesta: SOC-012, > 100 MB/h a destino externo).",
            "Bloquear SMB/RDP desde la VLAN de estaciones hacia servidores salvo excepciones documentadas.",
        ],
    },
]
