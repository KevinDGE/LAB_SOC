# CASE-001 — Fuerza bruta SSH con acceso exitoso a srv-web-01

> **Datos 100 % simulados.** Organización ficticia (Acme Andina S.A.); las IPs externas pertenecen a rangos de documentación RFC 5737. Reporte generado con `python -m soc_lab cases`.

| Campo | Valor |
|---|---|
| Severidad | Crítica |
| Estado | Cerrado |
| Clasificación | Verdadero positivo — compromiso de cuenta |
| Fecha | 2026-10-14 (UTC) |
| Primera actividad maliciosa | 02:47:03 UTC |
| Primera alerta | 02:47:03 UTC (tiempo de detección: 0.0 min) |
| Última actividad | 03:31:02 UTC (duración: 44 min) |
| Alertas correlacionadas | 3 (SOC-001, SOC-004, SOC-005) |
| Eventos revisados | 736 |

## 1. Resumen ejecutivo

Una IP externa (203.0.113.77) escaneó el servidor web público srv-web-01, identificó SSH expuesto a Internet y lanzó un ataque de diccionario contra seis usuarios. Tras unos 15 minutos obtuvo acceso con la cuenta de despliegue «deploy», que conservaba autenticación por contraseña y una contraseña débil. A los tres minutos el servidor descargó ~2,4 MB desde un host externo, compatible con la transferencia de herramientas del atacante.

## 2. Alcance

**Activos afectados:**

- srv-web-01 (10.10.2.10) — servidor web público, DMZ

**Cuentas afectadas:**

- deploy (cuenta local de despliegue)

**Fuera de alcance:** No se observa movimiento desde srv-web-01 hacia la red interna (10.10.1.0/24) en los registros del firewall.

## 3. Línea de tiempo (UTC)

| Hora | Tipo | Evento | Detalle | ATT&CK |
|---|---|---|---|---|
| 02:47:03–02:47:37 | 🚨 Alerta | SOC-005 · Escaneo de puertos contra un host (Media) | 203.0.113.77 sondeó 88 puertos distintos de 10.10.2.10 en 0.6 min (88 conexiones). | T1046 |
| 02:47:19–02:47:36 | Actividad | Puertos expuestos confirmados por el atacante | El escaneo obtuvo respuesta en los puertos 80, 443 de 10.10.2.10 (además de 22/SSH). | T1046 |
| 03:05:03–03:19:26 | Actividad | Ataque de diccionario SSH | 214 contraseñas fallidas entre 03:05:03 y 03:19:26 contra los usuarios admin, deploy, oracle, root, test, ubuntu. | T1110.001 |
| 03:05:03–03:19:26 | 🚨 Alerta | SOC-001 · Fuerza bruta SSH desde un mismo origen (Media) | 214 intentos SSH fallidos desde 203.0.113.77 contra srv-web-01 en 14.4 min (usuarios: oracle, admin, root (+3)). | T1110.001 |
| 03:05:03–03:21:14 | 🚨 Alerta | SOC-004 · Autenticación exitosa tras múltiples fallos (Crítica) | 214 fallos desde 203.0.113.77 seguidos de 1 logon(s) exitoso(s) como deploy en srv-web-01. | T1110, T1078 |
| 03:21:14 | Evento | Acceso SSH exitoso con contraseña | deploy autenticado por password desde 203.0.113.77:40022. Esta cuenta solo usa clave pública desde JUMP01 en su actividad normal. | T1078 |
| 03:24:40 | Evento | Descarga de herramientas desde infraestructura externa | srv-web-01 → 198.51.100.23:443 (2.4 MB). | T1105 |
| 03:31:02 | Evento | Descarga de herramientas desde infraestructura externa | srv-web-01 → 198.51.100.23:443 (0.1 MB). | T1105 |

## 4. Análisis técnico

**Reconocimiento.** El firewall registra conexiones a decenas de puertos distintos de 10.10.2.10 en menos de un minuto desde 203.0.113.77, con puertos de origen casi constantes (40000–40100): patrón de un escáner SYN automatizado. Solo respondieron 22, 80 y 443.

**Acceso a credenciales.** SOC-001 se disparó al décimo fallo. El diccionario combinó usuarios inexistentes (admin, test, oracle → `invalid user`) con cuentas reales (root, ubuntu, deploy), lo que sugiere una lista genérica y no reconocimiento previo de la organización.

**Compromiso.** SOC-004 correlacionó los fallos con el `Accepted password for deploy` desde la misma IP. La línea base del día muestra que deploy solo se autentica con `publickey` desde JUMP01 (10.10.5.10); un acceso por contraseña desde Internet es anómalo por sí mismo.

**Post-explotación.** La conexión saliente de srv-web-01 a 198.51.100.23:443 con 2,4 MB de transferencia ocurre 3 minutos después del acceso. No existe regla para este patrón (brecha de detección registrada abajo).

**Evidencia cruda (extracto):**

```text
2026-10-14T02:47:03Z fw01 action=deny proto=tcp src=203.0.113.77 spt=40048 dst=10.10.2.10 dpt=37 bytes=0 rule=default-deny
2026-10-14T02:47:03Z fw01 action=deny proto=tcp src=203.0.113.77 spt=40075 dst=10.10.2.10 dpt=111 bytes=0 rule=default-deny
2026-10-14T03:05:03Z srv-web-01 sshd[2074]: Failed password for ubuntu from 203.0.113.77 port 42794 ssh2
2026-10-14T03:05:07Z srv-web-01 sshd[2075]: Failed password for invalid user oracle from 203.0.113.77 port 43193 ssh2
2026-10-14T03:05:11Z srv-web-01 sshd[2076]: Failed password for invalid user test from 203.0.113.77 port 60624 ssh2
2026-10-14T03:21:14Z srv-web-01 sshd[2288]: Accepted password for deploy from 203.0.113.77 port 40022 ssh2
2026-10-14T03:24:40Z fw01 action=allow proto=tcp src=10.10.2.10 spt=51522 dst=198.51.100.23 dpt=443 bytes=2418331 rule=allow-dmz-out
2026-10-14T03:31:02Z fw01 action=allow proto=tcp src=10.10.2.10 spt=51588 dst=198.51.100.23 dpt=443 bytes=88120 rule=allow-dmz-out
```

## 5. Mapeo MITRE ATT&CK

| Táctica | Técnica | Evidencia |
|---|---|---|
| Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | SOC-004, contexto |
| Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | SOC-004 |
| Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing | SOC-001, contexto |
| Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery | SOC-005, contexto |
| Command and Control | [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer | contexto (sin alerta) |

## 6. Indicadores de compromiso

| Indicador | Tipo | Rol | Visto (UTC) |
|---|---|---|---|
| `203.0.113.77` | IPv4 externa (RFC 5737) | origen del ataque | 02:47:03–03:21:14 |
| `198.51.100.23` | IPv4 externa (RFC 5737) | destino externo (C2 / staging) | 03:24:40–03:31:02 |
| `deploy` | Cuenta | credencial comprometida | — |

## 7. Respuesta

**Contención**

- [x] Bloquear 203.0.113.77 y 198.51.100.23 en el firewall perimetral.
- [x] Aislar srv-web-01 de la DMZ y cerrar sesiones activas de deploy.

**Erradicación**

- [x] Rotar la contraseña de deploy y deshabilitar `PasswordAuthentication` en sshd_config.
- [x] Revisar `~deploy/.ssh/authorized_keys`, crontab y binarios descargados en /tmp.

**Recuperación**

- [x] Reconstruir srv-web-01 desde imagen confiable y redeplegar la aplicación.
- [x] Restringir 22/TCP a JUMP01 mediante regla de firewall.

## 8. Lecciones aprendidas y brechas de detección

- SSH expuesto a Internet con autenticación por contraseña habilitada.
- Brecha de detección: no hay regla para conexiones salientes nuevas desde servidores de la DMZ tras un logon (propuesta: SOC-010 «Primera conexión saliente de servidor DMZ a destino no visto»).
- Añadir fail2ban/bloqueo automático tras SOC-001 para reducir la ventana de ataque.

## 9. Alertas relacionadas

| ID | Regla | Severidad | Inicio | Fin | Eventos |
|---|---|---|---|---|---|
| `SOC-005-cfad4845` | SOC-005 Escaneo de puertos contra un host | Media | 02:47:03 | 02:47:37 | 88 |
| `SOC-001-70bfdb1e` | SOC-001 Fuerza bruta SSH desde un mismo origen | Media | 03:05:03 | 03:19:26 | 214 |
| `SOC-004-a96dd72a` | SOC-004 Autenticación exitosa tras múltiples fallos | Crítica | 03:05:03 | 03:21:14 | 215 |
