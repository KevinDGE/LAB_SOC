# CASE-003 — Movimiento lateral desde WS-017 con credenciales de helpdesk

> **Datos 100 % simulados.** Organización ficticia (Acme Andina S.A.); las IPs externas pertenecen a rangos de documentación RFC 5737. Reporte generado con `python -m soc_lab cases`.

| Campo | Valor |
|---|---|
| Severidad | Crítica |
| Estado | Cerrado |
| Clasificación | Verdadero positivo — intrusión interna con exfiltración |
| Fecha | 2026-10-14 (UTC) |
| Primera actividad maliciosa | 13:38:12 UTC |
| Primera alerta | 14:10:06 UTC (tiempo de detección: 31.9 min) |
| Última actividad | 15:29:12 UTC (duración: 111 min) |
| Alertas correlacionadas | 6 (SOC-005, SOC-006, SOC-007, SOC-008, SOC-009) |
| Eventos revisados | 230 |

## 1. Resumen ejecutivo

La estación WS-017 (usuario q.herrera) comenzó a comunicarse con 192.0.2.150 cada minuto a partir de las 13:38 UTC. Desde ese equipo se barrió la subred de servidores por SMB, se escaneó DB01 y, con las credenciales de la cuenta de helpdesk adm.m.fuentes —que había iniciado sesión en WS-017 por soporte esa mañana—, el atacante se movió a FS01, APP01, DB01 y BACKUP01, ejecutó servicios remotos (PsExec y un servicio con PowerShell) y abrió una sesión RDP en DB01. Entre las 15:06 y las 15:20 DB01 envió ~880 MB a 192.0.2.150.

## 2. Alcance

**Activos afectados:**

- WS-017 (10.10.20.17) — paciente cero
- FS01
- APP01
- DB01 (exfiltración)
- BACKUP01 (ejecución remota)

**Cuentas afectadas:**

- q.herrera (usuario de WS-017)
- adm.m.fuentes (helpdesk, credenciales robadas)

**Fuera de alcance:** DC01 rechazó el logon; no hay evidencia de compromiso del dominio.

## 3. Línea de tiempo (UTC)

| Hora | Tipo | Evento | Detalle | ATT&CK |
|---|---|---|---|---|
| 10:15:26 | Evento | Sesión de soporte del helpdesk en WS-017 | RDP legítimo de adm.m.fuentes desde JUMP01 (10.10.5.10). Las credenciales de la cuenta privilegiada quedan en memoria (LSASS) del equipo. | — |
| 13:38:12–15:29:12 | Actividad | Beaconing HTTPS hacia 192.0.2.150 | 112 conexiones a 192.0.2.150:443 entre 13:38:12 y 15:29:12, cada ~60 s y con tamaño casi constante: patrón de implante C2. Sin alerta (brecha). | T1071.001 |
| 14:10:06–14:11:00 | 🚨 Alerta | SOC-006 · Barrido de hosts internos en un mismo puerto (Alta) | 10.10.20.17 contactó 60 hosts internos distintos en el puerto 445 en 0.9 min. | T1018, T1046 |
| 14:10:42–14:15:05 | 🚨 Alerta | SOC-005 · Escaneo de puertos contra un host (Alta) | 10.10.20.17 sondeó 43 puertos distintos de 10.10.1.40 en 4.4 min (43 conexiones). | T1046 |
| 14:31:07–14:44:18 | 🚨 Alerta | SOC-007 · Movimiento lateral - logons de red a múltiples hosts (Crítica) | adm.m.fuentes inició sesión de red desde 10.10.20.17 en 4 equipos (FS01, APP01, DB01 (+1)) en 13.2 min. | T1021.002, T1078.002 |
| 14:33:55 | Evento | Intento de acceso a DC01 denegado | 4625 con Status 0xC000015B: la cuenta de helpdesk no tiene derecho de logon en el DC. | T1078.002 |
| 14:41:09 | 🚨 Alerta | SOC-008 · Instalación de servicio sospechoso (ejecución remota) (Crítica) | Servicio PSEXESVC instalado en DB01 con ImagePath sospechoso: %SystemRoot%\PSEXESVC.exe | T1569.002, T1543.003 |
| 14:45:01 | 🚨 Alerta | SOC-008 · Instalación de servicio sospechoso (ejecución remota) (Crítica) | Servicio WinSvcUpd instalado en BACKUP01 con ImagePath sospechoso: %COMSPEC% /c powershell.exe -nop -w hidden -c "vssadmin list shadows" | T1569.002, T1543.003 |
| 14:52:33 | 🚨 Alerta | SOC-009 · RDP desde un origen no autorizado (Crítica) | Sesión RDP de adm.m.fuentes en DB01 desde 10.10.20.17 (origen distinto de JUMP01). | T1021.001 |
| 15:06:51–15:20:57 | Actividad | Exfiltración desde DB01 | 6 conexiones salientes de DB01 a 192.0.2.150:443 con 881 MB en total entre 15:06:51 y 15:20:57. Sin alerta (brecha). | T1041 |

## 4. Análisis técnico

**Vector inicial.** No es observable con las fuentes disponibles (no hay telemetría de correo ni EDR). El primer indicio es la conexión de WS-017 a 192.0.2.150; la regularidad de ~60 s sugiere un implante C2. El análisis del equipo debe confirmar el vector (phishing es la hipótesis principal).

**Descubrimiento.** SOC-006 detecta el barrido SMB de 60 IPs en menos de un minuto y SOC-005 el escaneo de puertos de DB01; la severidad de SOC-005 sube a *alta* por tratarse de un origen interno.

**Acceso a credenciales.** adm.m.fuentes atendió WS-017 por RDP a las 10:15 desde JUMP01 (legítimo). Que esa misma cuenta inicie sesión desde 10.10.20.17 —y no desde JUMP01— cuatro horas después indica robo de credenciales de memoria (T1003.001, inferido: sin EDR no hay evidencia directa).

**Movimiento lateral y ejecución.** SOC-007 agrupa los logons de red a 4 servidores en 13 minutos; SOC-008 marca la instalación de PSEXESVC en DB01 y de un servicio que ejecuta `vssadmin list shadows` en BACKUP01 (reconocimiento de copias de sombra, frecuente antes de ransomware); SOC-009 detecta RDP a DB01 desde una estación. El fallo en DC01 (0xC000015B) muestra que la cuenta no tenía privilegios de dominio: el segmentado de privilegios limitó el alcance.

**Exfiltración.** Seis conexiones de DB01 al mismo C2 suman ~880 MB. Ninguna regla actual mide volumen saliente; se identificó revisando el firewall a partir de la IP del C2.

**Evidencia cruda (extracto):**

```text
2026-10-14T13:38:12Z fw01 action=allow proto=tcp src=10.10.20.17 spt=57972 dst=192.0.2.150 dpt=443 bytes=1163 rule=allow-web-out
2026-10-14T13:39:09Z fw01 action=allow proto=tcp src=10.10.20.17 spt=55079 dst=192.0.2.150 dpt=443 bytes=2568 rule=allow-web-out
{"Channel": "Security", "Computer": "FS01.corp.local", "EventData": {"AuthenticationPackageName": "NTLM", "IpAddress": "10.10.20.17", "IpPort": "51938", "LogonType": 3, "TargetDomainName": "CORP", "TargetUserName": "adm.m.fuentes", "WorkstationName": "WS-017"}, "EventID": 4624, "EventRecordID": 10150, "Provider": "Microsoft-Windows-Security-Auditing", "TimeCreated": "2026-10-14T14:31:07Z"}
{"Channel": "Security", "Computer": "DC01.corp.local", "EventData": {"AuthenticationPackageName": "NTLM", "IpAddress": "10.10.20.17", "IpPort": "50111", "LogonType": 3, "Status": "0xC000015B", "SubStatus": "0x0", "TargetDomainName": "CORP", "TargetUserName": "adm.m.fuentes", "WorkstationName": "WS-017"}, "EventID": 4625, "EventRecordID": 10002, "Provider": "Microsoft-Windows-Security-Auditing", "TimeCreated": "2026-10-14T14:33:55Z"}
{"Channel": "Security", "Computer": "APP01.corp.local", "EventData": {"AuthenticationPackageName": "NTLM", "IpAddress": "10.10.20.17", "IpPort": "53658", "LogonType": 3, "TargetDomainName": "CORP", "TargetUserName": "adm.m.fuentes", "WorkstationName": "WS-017"}, "EventID": 4624, "EventRecordID": 10082, "Provider": "Microsoft-Windows-Security-Auditing", "TimeCreated": "2026-10-14T14:36:40Z"}
{"Channel": "System", "Computer": "DB01.corp.local", "EventData": {"AccountName": "LocalSystem", "ImagePath": "%SystemRoot%\\PSEXESVC.exe", "ServiceName": "PSEXESVC", "ServiceType": "user mode service", "StartType": "demand start"}, "EventID": 7045, "EventRecordID": 10019, "Provider": "Service Control Manager", "TimeCreated": "2026-10-14T14:41:09Z"}
{"Channel": "System", "Computer": "BACKUP01.corp.local", "EventData": {"AccountName": "LocalSystem", "ImagePath": "%COMSPEC% /c powershell.exe -nop -w hidden -c \"vssadmin list shadows\"", "ServiceName": "WinSvcUpd", "ServiceType": "user mode service", "StartType": "demand start"}, "EventID": 7045, "EventRecordID": 10002, "Provider": "Service Control Manager", "TimeCreated": "2026-10-14T14:45:01Z"}
2026-10-14T15:06:51Z fw01 action=allow proto=tcp src=10.10.1.40 spt=54610 dst=192.0.2.150 dpt=443 bytes=157932257 rule=allow-web-out
2026-10-14T15:08:05Z fw01 action=allow proto=tcp src=10.10.1.40 spt=64330 dst=192.0.2.150 dpt=443 bytes=126668786 rule=allow-web-out
```

## 5. Mapeo MITRE ATT&CK

| Táctica | Técnica | Evidencia |
|---|---|---|
| Execution | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) System Services: Service Execution | SOC-008 |
| Persistence | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Create or Modify System Process: Windows Service | SOC-008 |
| Defense Evasion | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) Valid Accounts: Domain Accounts | SOC-007, contexto |
| Credential Access | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) OS Credential Dumping: LSASS Memory | inferido por el analista |
| Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) Remote System Discovery | SOC-006 |
| Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery | SOC-005, SOC-006 |
| Lateral Movement | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) Remote Services: Remote Desktop Protocol | SOC-009 |
| Lateral Movement | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) Remote Services: SMB/Windows Admin Shares | SOC-007 |
| Command and Control | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) Application Layer Protocol: Web Protocols | contexto (sin alerta) |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) Exfiltration Over C2 Channel | contexto (sin alerta) |

## 6. Indicadores de compromiso

| Indicador | Tipo | Rol | Visto (UTC) |
|---|---|---|---|
| `192.0.2.150` | IPv4 externa (RFC 5737) | destino externo (C2 / staging) | 13:38:12–15:29:12 |
| `adm.m.fuentes` | Cuenta | credencial comprometida | — |
| `PSEXESVC` | Servicio Windows | ejecución remota | — |
| `WinSvcUpd` | Servicio Windows | ejecución remota | — |

## 7. Respuesta

**Contención**

- [x] Aislar WS-017, DB01 y BACKUP01 de la red; bloquear 192.0.2.150 en el perímetro y en DNS.
- [x] Deshabilitar adm.m.fuentes y resetear q.herrera; invalidar tickets Kerberos (klist purge / krbtgt si aplica).

**Erradicación**

- [x] Eliminar los servicios PSEXESVC y WinSvcUpd; adquirir memoria y disco de WS-017 para análisis forense.
- [x] Buscar el hash del implante y conexiones a 192.0.2.150 en el resto de estaciones.

**Recuperación**

- [x] Reinstalar WS-017; validar integridad de los respaldos en BACKUP01 antes de cualquier restauración.
- [x] Notificar a legal/privacidad por la posible exfiltración de la base de datos (DB01).

## 8. Lecciones aprendidas y brechas de detección

- Las cuentas privilegiadas no deben iniciar sesión interactiva en estaciones de usuario: usar LAPS, Remote Credential Guard o RDP en modo Restricted Admin para soporte.
- Brecha de detección: beaconing periódico (propuesta: SOC-011 sobre regularidad de conexiones salientes).
- Brecha de detección: volumen saliente anómalo desde servidores (propuesta: SOC-012, > 100 MB/h a destino externo).
- Bloquear SMB/RDP desde la VLAN de estaciones hacia servidores salvo excepciones documentadas.

## 9. Alertas relacionadas

| ID | Regla | Severidad | Inicio | Fin | Eventos |
|---|---|---|---|---|---|
| `SOC-006-b1f7fbd5` | SOC-006 Barrido de hosts internos en un mismo puerto | Alta | 14:10:06 | 14:11:00 | 60 |
| `SOC-005-a5c41f4a` | SOC-005 Escaneo de puertos contra un host | Alta | 14:10:42 | 14:15:05 | 43 |
| `SOC-007-a73fcca9` | SOC-007 Movimiento lateral - logons de red a múltiples hosts | Crítica | 14:31:07 | 14:44:18 | 4 |
| `SOC-008-2e19d89d` | SOC-008 Instalación de servicio sospechoso (ejecución remota) | Crítica | 14:41:09 | 14:41:09 | 1 |
| `SOC-008-1e87e674` | SOC-008 Instalación de servicio sospechoso (ejecución remota) | Crítica | 14:45:01 | 14:45:01 | 1 |
| `SOC-009-992b65e3` | SOC-009 RDP desde un origen no autorizado | Crítica | 14:52:33 | 14:52:33 | 1 |
