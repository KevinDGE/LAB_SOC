# Reglas de detección

> Documento generado automáticamente desde `soc_lab/detection/rules/*.yml` con `python -m soc_lab docs`. No editar a mano.

## Resumen

| ID | Regla | Severidad base | Táctica | Técnicas ATT&CK | Lógica |
|----|-------|----------------|---------|-----------------|--------|
| SOC-001 | Fuerza bruta SSH desde un mismo origen | medium | Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing | ≥ 10 eventos por `src_ip`, `host` en 5m |
| SOC-002 | Fallos de autenticación repetidos contra una cuenta Windows | medium | Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing | ≥ 10 eventos por `user`, `host` en 10m |
| SOC-003 | Password spraying (muchas cuentas desde un origen) | high | Credential Access | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying | ≥ 10 valores distintos de `user` por `src_ip` en 30m |
| SOC-004 | Autenticación exitosa tras múltiples fallos | critical | Credential Access, Initial Access | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force, [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | ≥ 10 × `fallos` seguido de `exito` por `src_ip` en 30m |
| SOC-005 | Escaneo de puertos contra un host | medium | Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery | ≥ 20 valores distintos de `dst_port` por `src_ip`, `dst_ip` en 5m |
| SOC-006 | Barrido de hosts internos en un mismo puerto | high | Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) Remote System Discovery, [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery | ≥ 10 valores distintos de `dst_ip` por `src_ip`, `dst_port` en 10m |
| SOC-007 | Movimiento lateral - logons de red a múltiples hosts | high | Lateral Movement, Defense Evasion | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) Remote Services: SMB/Windows Admin Shares, [T1078.002](https://attack.mitre.org/techniques/T1078/002/) Valid Accounts: Domain Accounts | ≥ 3 valores distintos de `host` por `user`, `src_ip` en 30m |
| SOC-008 | Instalación de servicio sospechoso (ejecución remota) | high | Execution, Persistence | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) System Services: Service Execution, [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Create or Modify System Process: Windows Service | ≥ 1 eventos por `host` en 10m |
| SOC-009 | RDP desde un origen no autorizado | high | Lateral Movement | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) Remote Services: Remote Desktop Protocol | ≥ 1 eventos por `src_ip`, `host` en 30m |

## Cobertura MITRE ATT&CK

| Táctica | Técnica | Reglas |
|---------|---------|--------|
| Credential Access | T1110.001 Brute Force: Password Guessing | SOC-001, SOC-002 |
| Credential Access | T1110.003 Brute Force: Password Spraying | SOC-003 |
| Credential Access | T1110 Brute Force | SOC-004 |
| Defense Evasion | T1078.002 Valid Accounts: Domain Accounts | SOC-007 |
| Discovery | T1018 Remote System Discovery | SOC-006 |
| Discovery | T1046 Network Service Discovery | SOC-005, SOC-006 |
| Execution | T1569.002 System Services: Service Execution | SOC-008 |
| Initial Access | T1078 Valid Accounts | SOC-004 |
| Lateral Movement | T1021.001 Remote Services: Remote Desktop Protocol | SOC-009 |
| Lateral Movement | T1021.002 Remote Services: SMB/Windows Admin Shares | SOC-007 |
| Persistence | T1543.003 Create or Modify System Process: Windows Service | SOC-008 |

## SOC-001 — Fuerza bruta SSH desde un mismo origen

**Severidad:** medium · **Estado:** stable · **Fuentes:** sshd · **Archivo:** `soc_lab/detection/rules/SOC-001_ssh_bruteforce.yml`

Detecta múltiples autenticaciones SSH fallidas desde una misma IP contra un mismo servidor en una ventana corta. Es el patrón clásico de adivinación de contraseñas con diccionario contra servicios expuestos a Internet.

**ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing

**Lógica:**

```yaml
logic:
  type: threshold
  filter:
    source: sshd
    outcome: failure
  group_by:
  - src_ip
  - host
  window: 5m
  threshold: 10
```

**Falsos positivos conocidos:**

- Scripts de automatización con credenciales caducadas.
- Usuarios legítimos que olvidaron la contraseña (rara vez superan 10 intentos en 5 min).

**Triage:**

- ¿La IP de origen es interna o externa? Consultar reputación y geolocalización.
- ¿Hubo algún inicio de sesión exitoso desde la misma IP (ver SOC-004)?
- ¿Los usuarios probados existen en el sistema (invalid_user)?

**Respuesta:**

- Bloquear la IP en el firewall perimetral si es externa.
- Restringir SSH a la VPN o al jump host y exigir autenticación por clave.

**Referencias:** https://attack.mitre.org/techniques/T1110/001/

## SOC-002 — Fallos de autenticación repetidos contra una cuenta Windows

**Severidad:** medium · **Estado:** stable · **Fuentes:** windows · **Archivo:** `soc_lab/detection/rules/SOC-002_windows_bruteforce.yml`

Detecta 10 o más eventos 4625 para la misma cuenta en el mismo equipo en 10 minutos. Indica adivinación de contraseña dirigida a una cuenta concreta, aunque también es típico de credenciales caducadas guardadas en tareas programadas o servicios.

**ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing

**Lógica:**

```yaml
logic:
  type: threshold
  filter:
    source: windows
    event_code: '4625'
  group_by:
  - user
  - host
  window: 10m
  threshold: 10
```

**Falsos positivos conocidos:**

- Cuentas de servicio con contraseña expirada (SubStatus 0xC0000071) o cambiada (0xC000006A).
- Unidades de red mapeadas con credenciales antiguas.

**Triage:**

- Revisar Status/SubStatus del 4625 (contraseña errónea vs. expirada vs. cuenta bloqueada).
- ¿El origen es un servidor que ejecuta tareas con esa cuenta?
- ¿Existe un 4624 posterior para la misma cuenta desde el mismo origen?

**Respuesta:**

- Si es benigno, actualizar la credencial y documentar el ajuste.
- Si es malicioso, bloquear el origen y forzar cambio de contraseña.

**Referencias:** https://attack.mitre.org/techniques/T1110/001/ · https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625

## SOC-003 — Password spraying (muchas cuentas desde un origen)

**Severidad:** high · **Estado:** stable · **Fuentes:** windows, sshd · **Archivo:** `soc_lab/detection/rules/SOC-003_password_spraying.yml`

Detecta un origen que falla la autenticación contra 10 o más cuentas distintas en 30 minutos. El atacante prueba una o pocas contraseñas comunes contra muchos usuarios para evitar los bloqueos por cuenta, por lo que las reglas por usuario (SOC-002) no lo ven. Agnóstica de la fuente gracias al esquema normalizado.

**ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying

**Lógica:**

```yaml
logic:
  type: distinct
  filter:
    category: authentication
    outcome: failure
  group_by:
  - src_ip
  distinct_field: user
  window: 30m
  threshold: 10
```

**Falsos positivos conocidos:**

- Proxies o NAT corporativos que agregan a muchos usuarios (documentar la IP en una allowlist).
- Sistemas de SSO mal configurados tras un cambio de política.

**Triage:**

- ¿Cuántas cuentas probadas existen realmente? ¿Siguen un patrón de directorio?
- ¿Alguna cuenta tuvo un logon exitoso desde el mismo origen (SOC-004)?
- ¿El servicio atacado está expuesto a Internet (OWA, VPN, SSO)?

**Respuesta:**

- Bloquear el origen y revisar las cuentas con éxito posterior.
- Exigir MFA en servicios expuestos y aplicar listas de contraseñas prohibidas.

**Referencias:** https://attack.mitre.org/techniques/T1110/003/

## SOC-004 — Autenticación exitosa tras múltiples fallos

**Severidad:** critical · **Estado:** stable · **Fuentes:** windows, sshd · **Archivo:** `soc_lab/detection/rules/SOC-004_success_after_failures.yml`

Correlación en secuencia: 10 o más fallos de autenticación desde un origen seguidos de un inicio de sesión exitoso desde ese mismo origen en 30 minutos. Convierte una alerta de "intento" (SOC-001/002/003) en una de "probable compromiso" de credenciales válidas.

**ATT&CK:** [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force, [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts

**Lógica:**

```yaml
logic:
  type: sequence
  filter:
    category: authentication
  group_by:
  - src_ip
  window: 30m
  steps:
  - name: fallos
    filter:
      outcome: failure
    min_count: 10
  - name: exito
    filter:
      outcome: success
```

**Excepciones:**

```yaml
- src_ip:
    in: $admin_sources
```

**Falsos positivos conocidos:**

- Usuario que tras varios errores recuerda su contraseña (raro con umbral 10).
- Pruebas de penetración autorizadas.

**Triage:**

- Identificar la cuenta comprometida y la actividad posterior al logon.
- Revisar conexiones salientes del host afectado tras el acceso.
- Confirmar con el dueño de la cuenta si reconoce el acceso.

**Respuesta:**

- Deshabilitar o resetear la cuenta y cerrar sesiones activas.
- Aislar el host si hay actividad posterior sospechosa.
- Abrir incidente (severidad crítica).

**Referencias:** https://attack.mitre.org/techniques/T1110/ · https://attack.mitre.org/techniques/T1078/

## SOC-005 — Escaneo de puertos contra un host

**Severidad:** medium · **Estado:** stable · **Fuentes:** firewall · **Archivo:** `soc_lab/detection/rules/SOC-005_port_scan.yml`

Detecta un origen que contacta 20 o más puertos de destino distintos en un mismo host en 5 minutos (conexiones permitidas o denegadas). Si el origen es interno la severidad sube a alta: indica un equipo comprometido haciendo reconocimiento dentro de la red.

**ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery

**Lógica:**

```yaml
logic:
  type: distinct
  filter:
    source: firewall
  group_by:
  - src_ip
  - dst_ip
  distinct_field: dst_port
  window: 5m
  threshold: 20
```

**Excepciones:**

```yaml
- src_ip:
    in: $authorized_scanners
```

**Ajustes de severidad:** `{'src_ip': {'cidr': '$internal_networks'}}` → high

**Falsos positivos conocidos:**

- Escáneres de vulnerabilidades autorizados (suprimidos vía lista authorized_scanners).
- Herramientas de inventario o monitorización mal configuradas.

**Triage:**

- ¿Qué puertos respondieron (outcome=allowed)? ¿Hubo conexiones posteriores a ellos?
- Si el origen es interno, ¿quién usa el equipo y hay otras alertas sobre él?

**Respuesta:**

- Externo - bloquear IP y revisar exposición de servicios.
- Interno - aislar el equipo y escalar a incidente.

**Referencias:** https://attack.mitre.org/techniques/T1046/

## SOC-006 — Barrido de hosts internos en un mismo puerto

**Severidad:** high · **Estado:** stable · **Fuentes:** firewall · **Archivo:** `soc_lab/detection/rules/SOC-006_internal_host_sweep.yml`

Detecta un origen que contacta 10 o más IPs internas distintas en el mismo puerto en 10 minutos (p. ej. 445/SMB o 3389/RDP). Es el reconocimiento típico previo al movimiento lateral. Solo considera destinos internos para no disparar con la navegación web normal.

**ATT&CK:** [T1018](https://attack.mitre.org/techniques/T1018/) Remote System Discovery, [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery

**Lógica:**

```yaml
logic:
  type: distinct
  filter:
    source: firewall
    dst_ip:
      cidr: $internal_networks
  group_by:
  - src_ip
  - dst_port
  distinct_field: dst_ip
  window: 10m
  threshold: 10
```

**Excepciones:**

```yaml
- src_ip:
    in: $authorized_scanners
```

**Falsos positivos conocidos:**

- Escáneres autorizados, agentes de inventario o servidores de despliegue (SCCM).

**Triage:**

- ¿El origen es una estación de usuario? Las estaciones no deberían barrer subredes.
- ¿Siguen logons de red (4624 tipo 3) desde ese origen a los hosts que respondieron?

**Respuesta:**

- Aislar el equipo de origen y preservar evidencia (memoria y disco).

**Referencias:** https://attack.mitre.org/techniques/T1018/ · https://attack.mitre.org/techniques/T1046/

## SOC-007 — Movimiento lateral - logons de red a múltiples hosts

**Severidad:** high · **Estado:** stable · **Fuentes:** windows · **Archivo:** `soc_lab/detection/rules/SOC-007_lateral_network_logons.yml`

Detecta una misma cuenta iniciando sesión de red (4624, LogonType 3) desde un mismo origen en 3 o más equipos distintos en 30 minutos. Es la huella de uso de credenciales robadas sobre SMB/recursos administrativos (PsExec, WMI, copia a ADMIN$). Excluye cuentas de servicio y el jump host de administración.

**ATT&CK:** [T1021.002](https://attack.mitre.org/techniques/T1021/002/) Remote Services: SMB/Windows Admin Shares, [T1078.002](https://attack.mitre.org/techniques/T1078/002/) Valid Accounts: Domain Accounts

**Lógica:**

```yaml
logic:
  type: distinct
  filter:
    source: windows
    event_code: '4624'
    logon_type: 3
  group_by:
  - user
  - src_ip
  distinct_field: host
  window: 30m
  threshold: 3
```

**Excepciones:**

```yaml
- user:
    startswith: $service_account_prefixes
- src_ip:
    in: $admin_sources
```

**Ajustes de severidad:** `{'host': {'in': '$crown_jewels'}}` → critical

**Falsos positivos conocidos:**

- Administradores trabajando fuera del jump host (debería corregirse por política).
- Herramientas de gestión que usan cuentas nominales.

**Triage:**

- ¿La cuenta es privilegiada? ¿El origen es su equipo habitual?
- Buscar instalación de servicios (7045) o tareas programadas en los destinos.
- Revisar si la cuenta inició sesión antes en el equipo origen (robo de credenciales en memoria).

**Respuesta:**

- Deshabilitar la cuenta, rotar credenciales privilegiadas y aislar el origen.

**Referencias:** https://attack.mitre.org/techniques/T1021/002/ · https://attack.mitre.org/techniques/T1078/002/

## SOC-008 — Instalación de servicio sospechoso (ejecución remota)

**Severidad:** high · **Estado:** stable · **Fuentes:** windows · **Archivo:** `soc_lab/detection/rules/SOC-008_suspicious_service_install.yml`

Detecta eventos 7045 (nuevo servicio) cuyo ImagePath corresponde a herramientas de ejecución remota (PsExec) o a intérpretes de comandos (cmd.exe, PowerShell, %COMSPEC%), o reside en rutas temporales. Los servicios legítimos apuntan a binarios instalados en Program Files o System32.

**ATT&CK:** [T1569.002](https://attack.mitre.org/techniques/T1569/002/) System Services: Service Execution, [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Create or Modify System Process: Windows Service

**Lógica:**

```yaml
logic:
  type: threshold
  filter:
    source: windows
    event_code: '7045'
    extra.image_path:
      contains_any:
      - PSEXESVC
      - \ADMIN$\
      - '%COMSPEC%'
      - cmd.exe
      - powershell
      - \Temp\
      - \Users\Public\
  group_by:
  - host
  window: 10m
  threshold: 1
```

**Ajustes de severidad:** `{'host': {'in': '$crown_jewels'}}` → critical

**Falsos positivos conocidos:**

- Uso legítimo de PsExec por el equipo de TI (debería hacerse desde el jump host y con ticket).

**Triage:**

- ¿Qué cuenta inició sesión en el host justo antes (4624 tipo 3)?
- Decodificar la línea de comando y buscar el binario en otros equipos.

**Respuesta:**

- Aislar el host, detener y eliminar el servicio, recolectar el binario para análisis.

**Referencias:** https://attack.mitre.org/techniques/T1569/002/ · https://attack.mitre.org/techniques/T1543/003/

## SOC-009 — RDP desde un origen no autorizado

**Severidad:** high · **Estado:** stable · **Fuentes:** windows · **Archivo:** `soc_lab/detection/rules/SOC-009_rdp_unauthorized_source.yml`

Detecta inicios de sesión RDP (4624, LogonType 10) cuyo origen no es el jump host de administración. La política de Acme Andina exige que toda sesión remota interactiva pase por JUMP01, por lo que cualquier otro origen es una desviación que merece investigación.

**ATT&CK:** [T1021.001](https://attack.mitre.org/techniques/T1021/001/) Remote Services: Remote Desktop Protocol

**Lógica:**

```yaml
logic:
  type: threshold
  filter:
    source: windows
    event_code: '4624'
    logon_type: 10
  group_by:
  - src_ip
  - host
  window: 30m
  threshold: 1
```

**Excepciones:**

```yaml
- src_ip:
    in: $admin_sources
```

**Ajustes de severidad:** `{'host': {'in': '$crown_jewels'}}` → critical

**Falsos positivos conocidos:**

- Soporte de emergencia sin pasar por el jump host (debe estar documentado en un ticket).

**Triage:**

- ¿El origen es una estación de usuario? ¿Qué otras alertas tiene?
- ¿La cuenta usada corresponde a la persona asignada a la estación?

**Respuesta:**

- Cerrar la sesión, aislar el origen y revisar la actividad realizada durante la sesión.

**Referencias:** https://attack.mitre.org/techniques/T1021/001/
