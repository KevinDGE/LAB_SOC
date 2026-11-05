# CASE-002 — Password spraying contra OWA con dos cuentas comprometidas

> **Datos 100 % simulados.** Organización ficticia (Acme Andina S.A.); las IPs externas pertenecen a rangos de documentación RFC 5737. Reporte generado con `python -m soc_lab cases`.

| Campo | Valor |
|---|---|
| Severidad | Crítica |
| Estado | Cerrado |
| Clasificación | Verdadero positivo — compromiso de cuentas |
| Fecha | 2026-10-14 (UTC) |
| Primera actividad maliciosa | 11:03:15 UTC |
| Primera alerta | 11:03:15 UTC (tiempo de detección: 0.0 min) |
| Última actividad | 12:22:30 UTC (duración: 79 min) |
| Alertas correlacionadas | 2 (SOC-003, SOC-004) |
| Eventos revisados | 126 |

## 1. Resumen ejecutivo

Entre las 11:03 y las 11:40 UTC la IP externa 198.51.100.66 probó una única contraseña contra las 40 cuentas de empleados a través de OWA (EXCH01), a razón de una cuenta por minuto para no activar los bloqueos por cuenta. Dos cuentas —r.medina y e.vega— usaban esa contraseña. El atacante volvió a acceder al buzón de r.medina cuatro veces más durante la siguiente hora.

## 2. Alcance

**Activos afectados:**

- EXCH01 (10.10.2.20) — OWA expuesto en la DMZ

**Cuentas afectadas:**

- r.medina
- e.vega

**Fuera de alcance:** Las otras 38 cuentas fallaron; no hay logons de r.medina ni e.vega desde orígenes anómalos fuera de EXCH01.

## 3. Línea de tiempo (UTC)

| Hora | Tipo | Evento | Detalle | ATT&CK |
|---|---|---|---|---|
| 11:03:15–11:40:35 | Actividad | Comienza el spraying contra OWA | 38 logons fallidos (LogonType 8) contra 38 cuentas distintas entre 11:03:15 y 11:40:35; una cuenta cada ~61 s. | T1110.003 |
| 11:03:15–11:40:35 | 🚨 Alerta | SOC-003 · Password spraying (muchas cuentas desde un origen) (Alta) | 198.51.100.66 falló la autenticación contra 38 cuentas distintas en EXCH01 durante 37.3 min. | T1110.003 |
| 11:03:15–12:22:30 | 🚨 Alerta | SOC-004 · Autenticación exitosa tras múltiples fallos (Crítica) | 38 fallos desde 198.51.100.66 seguidos de 6 logon(s) exitoso(s) como r.medina, e.vega en EXCH01. | T1110, T1078 |
| 11:16:24 | Evento | Credencial válida encontrada | 4624 LogonType 8 en EXCH01 para r.medina: la contraseña probada es válida. | T1078 |
| 11:31:23 | Evento | Credencial válida encontrada | 4624 LogonType 8 en EXCH01 para e.vega: la contraseña probada es válida. | T1078 |
| 12:01:30–12:22:30 | Actividad | Uso del buzón comprometido | 4 sesiones OWA adicionales como r.medina entre 12:01:30 y 12:22:30. | T1078 |

## 4. Análisis técnico

**Patrón de spraying.** Ninguna cuenta supera un fallo, por lo que SOC-002 (fallos por cuenta) no se dispara; sí lo hace SOC-003 al contar usuarios distintos por origen. Este es el motivo de tener ambas reglas: cubren el mismo objetivo (T1110) desde ejes distintos.

**Códigos de estado.** Todos los 4625 tienen `SubStatus 0xC000006A` (contraseña incorrecta), no `0xC0000064` (usuario inexistente): el atacante conocía la nomenclatura `inicial.apellido`, probablemente por OSINT (LinkedIn, firmas de correo).

**Compromiso.** SOC-004 correlaciona los fallos con los logons exitosos desde la misma IP y agrupa en una sola alerta los accesos posteriores al buzón de r.medina, que indican uso activo de la cuenta (lectura de correo, posible preparación de BEC).

**Evidencia cruda (extracto):**

```text
{"Channel": "Security", "Computer": "EXCH01.corp.local", "EventData": {"AuthenticationPackageName": "NTLM", "IpAddress": "198.51.100.66", "IpPort": "53960", "LogonType": 8, "Status": "0xC000006D", "SubStatus": "0xC000006A", "TargetDomainName": "CORP", "TargetUserName": "h.torres", "WorkstationName": "-"}, "EventID": 4625, "EventRecordID": 10001, "Provider": "Microsoft-Windows-Security-Auditing", "TimeCreated": "2026-10-14T11:03:15Z"}
{"Channel": "Security", "Computer": "EXCH01.corp.local", "EventData": {"AuthenticationPackageName": "NTLM", "IpAddress": "198.51.100.66", "IpPort": "56526", "LogonType": 8, "Status": "0xC000006D", "SubStatus": "0xC000006A", "TargetDomainName": "CORP", "TargetUserName": "k.molina", "WorkstationName": "-"}, "EventID": 4625, "EventRecordID": 10002, "Provider": "Microsoft-Windows-Security-Auditing", "TimeCreated": "2026-10-14T11:04:12Z"}
{"Channel": "Security", "Computer": "EXCH01.corp.local", "EventData": {"AuthenticationPackageName": "NTLM", "IpAddress": "198.51.100.66", "IpPort": "52507", "LogonType": 8, "TargetDomainName": "CORP", "TargetUserName": "r.medina", "WorkstationName": "-"}, "EventID": 4624, "EventRecordID": 10015, "Provider": "Microsoft-Windows-Security-Auditing", "TimeCreated": "2026-10-14T11:16:24Z"}
{"Channel": "Security", "Computer": "EXCH01.corp.local", "EventData": {"AuthenticationPackageName": "NTLM", "IpAddress": "198.51.100.66", "IpPort": "55826", "LogonType": 8, "TargetDomainName": "CORP", "TargetUserName": "e.vega", "WorkstationName": "-"}, "EventID": 4624, "EventRecordID": 10030, "Provider": "Microsoft-Windows-Security-Auditing", "TimeCreated": "2026-10-14T11:31:23Z"}
```

## 5. Mapeo MITRE ATT&CK

| Táctica | Técnica | Evidencia |
|---|---|---|
| Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | SOC-004, contexto |
| Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | SOC-004 |
| Credential Access | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying | SOC-003, contexto |

## 6. Indicadores de compromiso

| Indicador | Tipo | Rol | Visto (UTC) |
|---|---|---|---|
| `198.51.100.66` | IPv4 externa (RFC 5737) | origen del ataque | 11:03:15–12:22:30 |
| `e.vega` | Cuenta | credencial comprometida | — |
| `r.medina` | Cuenta | credencial comprometida | — |

## 7. Respuesta

**Contención**

- [x] Bloquear 198.51.100.66; forzar cierre de sesión y reseteo de r.medina y e.vega.
- [x] Revisar reglas de reenvío y delegaciones creadas en ambos buzones.

**Erradicación**

- [x] Buscar correos enviados por r.medina tras las 11:20 (phishing interno / BEC).
- [x] Aplicar lista de contraseñas prohibidas (patrones estacionales como «Primavera2026!»).

**Recuperación**

- [x] Habilitar MFA obligatorio en OWA y publicar OWA tras un proxy con protección de identidad.

## 8. Lecciones aprendidas y brechas de detección

- OWA accesible desde Internet sin MFA.
- Política de contraseñas que admite patrones predecibles.
- Mejora de detección: alertar también cuando una IP externa nueva accede a un buzón tras una alerta SOC-003 aunque no supere el umbral de fallos.

## 9. Alertas relacionadas

| ID | Regla | Severidad | Inicio | Fin | Eventos |
|---|---|---|---|---|---|
| `SOC-003-a8f86196` | SOC-003 Password spraying (muchas cuentas desde un origen) | Alta | 11:03:15 | 11:40:35 | 38 |
| `SOC-004-e7de154a` | SOC-004 Autenticación exitosa tras múltiples fallos | Crítica | 11:03:15 | 12:22:30 | 44 |
