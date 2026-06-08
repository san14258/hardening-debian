#!/bin/bash
# =============================================================================
# 05_ssh.sh — CIS Sección 5.2
# -----------------------------------------------------------------------------
# QUÉ HACE ESTE SCRIPT:
#   1. Hace backup de /etc/ssh/sshd_config antes de tocar nada.
#   2. Aplica una configuración SSH endurecida:
#        - Prohíbe login de root directamente
#        - Limita intentos de autenticación
#        - Deshabilita reenvío de X11/agentes/TCP
#        - Usa solo algoritmos criptográficos modernos
#        - Configura timeout de sesiones inactivas
#   3. VALIDA la configuración con sshd -t ANTES de reiniciar.
#      Si la config es inválida, restaura el backup automáticamente
#      (CRÍTICO: si rompemos SSH y estamos remotos, nos quedamos afuera).
#   4. Reinicia el servicio SSH.
# =============================================================================

[[ $EUID -ne 0 ]] && { echo "Ejecutar como root"; exit 1; }
DRY_RUN=${DRY_RUN:-0}
OK=0; WARN=0; ERR=0

run() {
    [[ $DRY_RUN -eq 1 ]] && echo "  [DRY-RUN] $*" || eval "$@"
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " 05_ssh.sh — CIS 5.2 — SSH endurecido"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo " Objetivo: endurecer SSH, que es el principal vector de"
echo " acceso a un servidor. Aplicamos las recomendaciones CIS:"
echo " sin login de root, criptografía moderna, timeouts, etc."
echo ""
echo " ATENCIÓN: si rompemos SSH y estamos conectados de forma"
echo " remota, podemos perder acceso. Por eso validamos con"
echo " 'sshd -t' antes de reiniciar y restauramos backup si falla."
echo ""

SSH_CONFIG="/etc/ssh/sshd_config"
BACKUP="${SSH_CONFIG}.pre-hardening"

# -----------------------------------------------------------------------------
# 5.1 — Backup
# -----------------------------------------------------------------------------
echo ">>> [1/3] Backup de la configuración SSH actual"
if [[ ! -f "$BACKUP" ]]; then
    run "cp $SSH_CONFIG $BACKUP"
    echo "    [OK] Backup guardado en $BACKUP"
    OK=$((OK+1))
else
    echo "    [OK] Backup ya existía: $BACKUP"
    OK=$((OK+1))
fi

# -----------------------------------------------------------------------------
# 5.2 — Aplicar configuración endurecida
# -----------------------------------------------------------------------------
echo ""
echo ">>> [2/3] Escribiendo configuración SSH endurecida"
echo "    Cambios clave:"
echo "      • PermitRootLogin no       → fuerza login con usuario normal + sudo"
echo "      • MaxAuthTries 4           → limita intentos por sesión"
echo "      • PermitEmptyPasswords no  → bloquea cuentas sin password"
echo "      • X11Forwarding no         → no permite GUI por SSH"
echo "      • AllowTcpForwarding no    → no permite usar SSH como tunelizador"
echo "      • ClientAliveInterval 300  → cierra sesiones inactivas a los 5 min"
echo "      • KexAlgorithms/Ciphers    → solo crypto moderna (curve25519, chacha20)"
echo ""

if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [DRY-RUN] Escribir nuevo $SSH_CONFIG"
else
    cat > "$SSH_CONFIG" << 'EOF'
# /etc/ssh/sshd_config — Endurecido por framework de hardening CIS 5.2

# --- Puerto y protocolo ---
Port 22
Protocol 2

# --- Criptografía moderna (CIS 5.2.13-5.2.15) ---
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# --- Autenticación (CIS 5.2.7-5.2.10) ---
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 4
MaxSessions 4
PubkeyAuthentication yes
HostbasedAuthentication no
IgnoreRhosts yes

# --- Restricciones de acceso (CIS 5.2.4-5.2.6) ---
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitUserEnvironment no
GatewayPorts no

# --- Timeout de sesión (CIS 5.2.16-5.2.17) ---
ClientAliveInterval 300
ClientAliveCountMax 3
LoginGraceTime 60

# --- Banner y logging (CIS 5.2.11-5.2.12) ---
Banner /etc/issue.net
PrintLastLog yes
LogLevel VERBOSE
SyslogFacility AUTH

# --- SFTP ---
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
    chmod 600 "$SSH_CONFIG"
fi
echo "    [OK] $SSH_CONFIG escrito y permisos 600 aplicados"
OK=$((OK+1))

# -----------------------------------------------------------------------------
# 5.3 — Validar y reiniciar
# -----------------------------------------------------------------------------
echo ""
echo ">>> [3/3] Validando configuración con 'sshd -t' antes de reiniciar"
echo "    Justificación: si reiniciamos SSH con una config inválida, el"
echo "    servicio no arranca y perdemos acceso. sshd -t verifica la"
echo "    sintaxis sin aplicar nada. Si falla, restauramos el backup."
echo ""

if [[ $DRY_RUN -eq 0 ]]; then
    if sshd -t 2>/dev/null; then
        echo "    [OK] Configuración SSH válida"
        OK=$((OK+1))
        # Reiniciar el servicio (probar 'ssh' y 'sshd' por compatibilidad)
        if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
            echo "    [OK] Servicio SSH reiniciado correctamente"
            OK=$((OK+1))
        else
            echo "    [ERROR] No se pudo reiniciar SSH"
            ERR=$((ERR+1))
        fi
    else
        echo "    [ERROR] La configuración es INVÁLIDA — restaurando backup"
        cp "$BACKUP" "$SSH_CONFIG"
        ERR=$((ERR+1))
    fi
else
    echo "  [DRY-RUN] sshd -t && systemctl restart sshd"
fi

echo ""
echo "─── Resumen 05_ssh.sh ─────────────────────────────────────"
echo "    OK: $OK   WARN: $WARN   ERR: $ERR"
echo ""

export SCRIPT_OK=$OK SCRIPT_WARN=$WARN SCRIPT_ERR=$ERR
