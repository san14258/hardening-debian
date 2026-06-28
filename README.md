# Hardening Debian - Scripts CIS Benchmark

Scripts de hardening automatizado para servidores Debian, basados en el **CIS Benchmark Level 1**.  
Cubren filesystem, servicios, red, logging, SSH, usuarios, PAM, firewall, fail2ban y actualizaciones.

---

## Estructura del Proyecto

```text
hardening/
├── hardening_main.sh          # Orquestador principal (incluye auditoría Lynis)
└── scripts/
    ├── 01_filesystem.sh       # CIS 1.x  — Módulos kernel y permisos de archivos críticos
    ├── 02_services.sh         # CIS 2.x  — Deshabilitar servicios y eliminar protocolos legacy
    ├── 03_network.sh          # CIS 3.x  — sysctl de red y kernel + mod_evasive
    ├── 04_logging.sh          # CIS 4.x  — auditd con reglas CIS + rsyslog
    ├── 05_ssh.sh              # CIS 5.2  — SSH endurecido (validación sshd -t + backup)
    ├── 06_users.sh            # CIS 5.4  — UID 0, sudo, login.defs, TMOUT
    ├── 07_pam.sh              # CIS 5.3  — pwquality + faillock + SHA-512
    ├── 08_firewall.sh         # nftables — deny by default
    ├── 09_fail2ban.sh         # fail2ban — jail [sshd] + jails Apache (si aplica)
    └── 10_updates.sh          # unattended-upgrades — parches de seguridad automáticos
    └── 11:lynis.sh            # Instala lynis y audita
```

---

## ¿Qué hace cada módulo?

### 01 - Filesystem
- Deshabilita módulos del kernel para sistemas de archivos poco comunes (`cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `squashfs`, `udf`) - reducen la superficie de ataque.
- Verifica que `/tmp`, `/var/tmp` y `/dev/shm` tengan las opciones `nodev`, `nosuid` y `noexec`, impidiendo ejecución de binarios en directorios de escritura libre.
- Ajusta permisos de archivos críticos (`/etc/passwd`, `/etc/shadow`, etc.) según CIS.
- Configura `UMASK 027` en `/etc/login.defs` - los archivos nuevos no son legibles por "otros" por defecto.

### 02 - Services
- Deshabilita servicios de red no necesarios en un servidor típico: `avahi`, `cups`, NFS, Samba, SNMP, entre otros.
- Elimina paquetes legacy inseguros que transmiten en claro: `telnet`, `rsh`, `talk`, `nis`.
- Muestra qué servicios permanecen escuchando en la red para revisión manual.

### 03 - Network
- Aplica parámetros `sysctl` en `/etc/sysctl.d/99-hardening.conf`: anti-spoofing, anti-redirect, ASLR, restricción de `ptrace`, `kptr_restrict`, entre otros.
- Deshabilita protocolos de red poco usados: `dccp`, `sctp`, `rds`, `tipc`.
- Instala `mod_evasive` (Apache) para mitigación de DoS si hay servidor web presente.

### 04 - Logging
- Instala `auditd` + `audispd-plugins`. Registra a nivel de syscall: quién ejecutó qué, cuándo y qué archivos tocó - indispensable para forense post-incidente.
- Carga reglas CIS: login, identidad, sudo, módulos, cambios de permisos, montajes y eliminaciones.
- Configura `auditd.conf` para rotación de logs y manejo de espacio en disco.
- Asegura `rsyslog` activo y permisos correctos en `/var/log`.
- Agrega `audit=1` al kernel vía GRUB para auditar desde el arranque.

### 05 - SSH
- Hace backup de `/etc/ssh/sshd_config` antes de cualquier cambio.
- Aplica configuración endurecida: deshabilita login directo de root, limita intentos de autenticación, deshabilita reenvío de X11/agentes/TCP, usa solo algoritmos criptográficos modernos, configura timeout de sesiones inactivas.
- **Valida la configuración con `sshd -t` antes de reiniciar** - si hay error, restaura el backup automáticamente (crítico en acceso remoto).

### 06 - Users
- Detecta y reporta cuentas con `UID 0` distintas de root (posibles backdoors).
- Bloquea cuentas con contraseña vacía.
- Cambia el shell de cuentas de sistema (`UID < 1000`) a `/usr/sbin/nologin`.
- Configura `sudo`: timeout de 15 min, logging habilitado, sintaxis validada.
- Configura `TMOUT=900` (cierra sesiones bash inactivas) y `HISTTIMEFORMAT` (timestamps en historial).

### 07 - PAM
- Instala `libpam-pwquality` y configura política estricta: 14+ caracteres, mayúsculas, minúsculas, dígitos y especiales, sin repeticiones ni palabras de diccionario.
- Configura `pam_faillock`: bloqueo de cuenta tras 5 intentos fallidos durante 15 minutos.
- Configura hashing SHA-512 con 10.000 rondas e historial de 5 contraseñas (no reutilización).

### 08 - Firewall
- Instala `nftables` (reemplazo moderno de `iptables`, integrado al kernel).
- Desactiva UFW si estaba activo para evitar conflictos.
- Política *deny by default*: descarta todo el tráfico entrante salvo SSH, loopback y tráfico ya establecido.
- **Valida la sintaxis con `nft -c` antes de aplicar** - un error de sintaxis no deja el servidor sin firewall.

### 09 - Fail2ban
- Instala `fail2ban` y configura el jail `[sshd]`: bloqueo de IP tras 5 intentos fallidos en 10 minutos, durante 1 hora.
- Si hay Apache instalado, habilita jails adicionales: `apache-auth` y `apache-badbots`.

### 10 - Updates
- Actualiza la lista de paquetes y aplica parches de seguridad pendientes.
- Instala y habilita `unattended-upgrades` para aplicar parches de seguridad automáticamente de forma diaria.
- Configura las fuentes para actualizar solo paquetes con vulnerabilidades (sin upgrades mayores que puedan romper compatibilidad).
- Reporta si quedan actualizaciones pendientes o si el sistema requiere reinicio.

---

## Instalación y Ejecución

### 1. Clonar el repositorio

```bash
git clone https://github.com/san14258/hardening-debian.git
cd hardening-debian
```

### 2. Asignar permisos de ejecución

```bash
chmod +x hardening_main.sh
chmod +x scripts/*.sh
```

### 3. Ejecutar el proceso de hardening

```bash
sudo ./hardening_main.sh
```

---

## Verificación y Logs

Una vez finalizada la ejecución, los registros del proceso se encuentran en:

```bash
ls -l /var/log/hardening/
```

Para visualizar las últimas líneas del log en tiempo real:

```bash
tail -f /var/log/hardening/hardening.log
```

---

## Hardening Index (Lynis)

La auditoría final es ejecutada automáticamente por `hardening_main.sh` al término del proceso.  
Lynis genera su reporte en:

```
/var/log/lynis-report.dat
/var/log/lynis.log
```

Para obtener el **Hardening Index**:

```bash
grep "hardening_index" /var/log/lynis-report.dat
```

Para revisar el reporte completo:

```bash
less /var/log/lynis-report.dat
```

---

## Flujo de Ejecución

```
hardening_main.sh
 ├── 01_filesystem.sh
 ├── 02_services.sh
 ├── 03_network.sh
 ├── 04_logging.sh
 ├── 05_ssh.sh
 ├── 06_users.sh
 ├── 07_pam.sh
 ├── 08_firewall.sh
 ├── 09_fail2ban.sh
 ├── 10_updates.sh
 └── Auditoría Lynis → /var/log/lynis-report.dat
```

---

## Requisitos

- Debian 11 (Bullseye) o Debian 12 (Bookworm)
- Acceso root o sudo
- Conexión a Internet (para instalación de paquetes)

---

## Referencias

- [CIS Debian Linux Benchmark](https://www.cisecurity.org/benchmark/debian_linux)
- [Lynis - Security Auditing Tool](https://cisofy.com/lynis/)
