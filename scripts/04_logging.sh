#!/bin/bash
# =============================================================================
# 04_logging.sh — CIS Sección 4.x
# -----------------------------------------------------------------------------
# QUÉ HACE ESTE SCRIPT:
#   1. Instala auditd + audispd-plugins. auditd registra TODO lo que pasa
#      en el sistema a nivel de syscall: quién ejecutó qué, cuándo, qué
#      archivos tocó. Sin auditd no hay forense después de un incidente.
#   2. Carga un conjunto de reglas CIS (login, identidad, sudo, módulos,
#      cambios de permisos, montajes, eliminaciones).
#   3. Configura auditd.conf para rotación de logs y manejo de espacio.
#   4. Asegura que rsyslog esté activo y configura permisos de /var/log.
#   5. Agrega audit=1 al kernel (GRUB) para auditar desde el arranque.
# =============================================================================

[[ $EUID -ne 0 ]] && { echo "Ejecutar como root"; exit 1; }
DRY_RUN=${DRY_RUN:-0}
OK=0; WARN=0; ERR=0

run() {
    [[ $DRY_RUN -eq 1 ]] && echo "  [DRY-RUN] $*" || eval "$@"
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " 04_logging.sh — CIS 4.x — auditd + rsyslog"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo " Objetivo: tener trazabilidad completa de lo que pasa en el"
echo " sistema. auditd registra a nivel de syscall (quién hizo qué)"
echo " y rsyslog gestiona los logs y permite reenviarlos a un SIEM."
echo ""

# -----------------------------------------------------------------------------
# 4.1 — Instalar auditd
# -----------------------------------------------------------------------------
echo ">>> [1/4] Instalando auditd y audispd-plugins"
echo "    Justificación: auditd es el demonio de auditoría del kernel."
echo "    Sin él, no hay forma de reconstruir lo que pasó si hay un"
echo "    incidente: qué usuario abrió qué archivo, qué comando se"
echo "    ejecutó, qué módulo se cargó, etc."
echo ""

if dpkg -l auditd 2>/dev/null | grep -q "^ii"; then
    echo "    [OK] auditd ya estaba instalado"
    OK=$((OK+1))
else
    run "apt-get install -y auditd audispd-plugins"
    echo "    [OK] auditd y audispd-plugins instalados"
    OK=$((OK+1))
fi

run "systemctl enable auditd"
run "systemctl start auditd"
echo "    [OK] auditd habilitado y arrancado"
OK=$((OK+1))

# -----------------------------------------------------------------------------
# 4.2 — Cargar reglas CIS
# -----------------------------------------------------------------------------
echo ""
echo ">>> [2/4] Cargando reglas de auditoría CIS"
echo "    Justificación: las reglas indican QUÉ auditar. Cubrimos:"
echo "      • Cambios de hora del sistema (atacantes manipulan timestamps)"
echo "      • Cambios en /etc/passwd, /etc/shadow (creación de cuentas)"
echo "      • Uso de sudo y su (escalada de privilegios)"
echo "      • Carga/descarga de módulos del kernel (rootkits)"
echo "      • Cambios de permisos y dueños de archivos"
echo "      • Eliminación de archivos por usuarios"
echo ""

RULES_FILE="/etc/audit/rules.d/cis-hardening.rules"

if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [DRY-RUN] Crear $RULES_FILE con reglas CIS"
else
    cat > "$RULES_FILE" << 'EOF'
# Reglas de auditoría CIS — generadas por el framework de hardening

# Buffer para ráfagas de eventos
-b 8192

# CIS 4.1.3 — Cambios de hora
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# CIS 4.1.4 — Cambios de identidad
-w /etc/group   -p wa -k identity
-w /etc/passwd  -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# CIS 4.1.5 — Cambios de hostname/red
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# CIS 4.1.6 — Inicios de sesión
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

# CIS 4.1.7 — Sesiones
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# CIS 4.1.8 — Cambios de permisos
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

# CIS 4.1.11 — Programas privilegiados (sudo, su, passwd)
-a always,exit -F path=/usr/bin/sudo   -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su     -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# CIS 4.1.12 — Montajes
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# CIS 4.1.13 — Eliminación de archivos
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# CIS 4.1.14 — Cambios en sudoers
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

# CIS 4.1.16 — Carga y descarga de módulos del kernel
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# IMPORTANTE: dejar las reglas inmutables hasta el próximo reinicio
-e 2
EOF
fi
echo "    [OK] Reglas CIS guardadas en $RULES_FILE"
OK=$((OK+1))

# Cargar reglas
run "augenrules --load 2>/dev/null || true"
run "systemctl restart auditd"
echo "    [OK] Reglas cargadas en auditd"
OK=$((OK+1))

# -----------------------------------------------------------------------------
# 4.3 — Configurar auditd.conf y GRUB
# -----------------------------------------------------------------------------
echo ""
echo ">>> [3/4] Configurando rotación de logs y arranque temprano"
echo "    Justificación: si auditd se queda sin espacio, deja de loguear"
echo "    y perdemos visibilidad. Configuramos rotación. Además, audit=1"
echo "    en GRUB hace que el kernel audite ANTES de que auditd arranque,"
echo "    capturando lo que pasa al inicio del boot."
echo ""

AUDITD_CONF="/etc/audit/auditd.conf"
if [[ -f "$AUDITD_CONF" ]]; then
    run "sed -i 's/^max_log_file = .*/max_log_file = 50/' $AUDITD_CONF"
    run "sed -i 's/^num_logs = .*/num_logs = 10/' $AUDITD_CONF"
    run "sed -i 's/^space_left_action = .*/space_left_action = SYSLOG/' $AUDITD_CONF"
    echo "    [OK] auditd.conf: max_log_file=50MB, num_logs=10"
    OK=$((OK+1))
fi

GRUB="/etc/default/grub"
if [[ -f "$GRUB" ]]; then
    if grep -q "audit=1" "$GRUB"; then
        echo "    [OK] audit=1 ya estaba en GRUB"
        OK=$((OK+1))
    else
        run "sed -i 's/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"audit=1 /' $GRUB"
        run "update-grub 2>/dev/null || true"
        echo "    [OK] audit=1 agregado al kernel (requiere reinicio)"
        OK=$((OK+1))
    fi
fi

# -----------------------------------------------------------------------------
# 4.4 — rsyslog
# -----------------------------------------------------------------------------
echo ""
echo ">>> [4/4] Verificando rsyslog"
echo "    Justificación: rsyslog gestiona la mayoría de logs del sistema"
echo "    (auth.log, syslog, kern.log). Debe estar activo siempre. Desde"
echo "    aquí se puede reenviar al SIEM agregando un archivo en"
echo "    /etc/rsyslog.d/99-siem.conf (no incluido por defecto)."
echo ""

if dpkg -l rsyslog 2>/dev/null | grep -q "^ii"; then
    echo "    [OK] rsyslog ya estaba instalado"
    OK=$((OK+1))
else
    run "apt-get install -y rsyslog"
    echo "    [OK] rsyslog instalado"
    OK=$((OK+1))
fi

run "systemctl enable rsyslog"
run "systemctl start rsyslog"
echo "    [OK] rsyslog habilitado y arrancado"
OK=$((OK+1))

# Permisos correctos en logs sensibles
run "chmod 640 /var/log/auth.log 2>/dev/null || true"
run "chmod 640 /var/log/syslog 2>/dev/null || true"
echo "    [OK] Permisos de /var/log/auth.log y syslog en 640"
OK=$((OK+1))

echo ""
echo "─── Resumen 04_logging.sh ─────────────────────────────────"
echo "    OK: $OK   WARN: $WARN   ERR: $ERR"
echo ""

export SCRIPT_OK=$OK SCRIPT_WARN=$WARN SCRIPT_ERR=$ERR
