#!/bin/bash
# =============================================================================
# 09_fail2ban.sh — fail2ban
# -----------------------------------------------------------------------------
# QUÉ HACE ESTE SCRIPT:
#   1. Instala fail2ban — un servicio que monitorea logs (auth.log,
#      access.log, etc.) y bloquea automáticamente las IPs que generan
#      patrones de ataque (intentos fallidos de SSH, escaneos web, etc.).
#   2. Configura el jail [sshd] para banear IPs tras 5 intentos fallidos
#      en 10 minutos, durante 1 hora.
#   3. Si hay Apache instalado, habilita jails adicionales (apache-auth,
#      apache-badbots) para protección web.
#
#   NOTA: PAM con faillock (script 07) bloquea CUENTAS locales tras
#   intentos fallidos. fail2ban bloquea IPs ENTERAS a nivel de firewall.
#   Son complementarios, no redundantes.
# =============================================================================

[[ $EUID -ne 0 ]] && { echo "Ejecutar como root"; exit 1; }
DRY_RUN=${DRY_RUN:-0}
OK=0; WARN=0; ERR=0

run() {
    [[ $DRY_RUN -eq 1 ]] && echo "  [DRY-RUN] $*" || eval "$@"
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " 09_fail2ban.sh — fail2ban (anti fuerza bruta de red)"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo " Objetivo: detectar automáticamente ataques de fuerza bruta"
echo " contra SSH (y otros servicios) leyendo los logs y banear"
echo " las IPs atacantes en el firewall."
echo ""
echo " Diferencia con pam_faillock (script 07):"
echo "   • pam_faillock bloquea la CUENTA local tras X intentos."
echo "   • fail2ban bloquea la IP atacante a nivel de firewall,"
echo "     impidiendo que siga probando con otras cuentas."
echo ""

# -----------------------------------------------------------------------------
# 9.1 — Instalar fail2ban
# -----------------------------------------------------------------------------
echo ">>> [1/3] Instalando fail2ban"
echo "    Justificación: SSH es el servicio más atacado en internet."
echo "    Sin fail2ban, los bots prueban miles de contraseñas. Con"
echo "    fail2ban, tras 5 intentos fallidos la IP queda bloqueada"
echo "    y los bots se mueven a otro objetivo."
echo ""

if dpkg -l fail2ban 2>/dev/null | grep -q "^ii"; then
    echo "    [OK] fail2ban ya estaba instalado"
    OK=$((OK+1))
else
    run "apt-get install -y fail2ban"
    echo "    [OK] fail2ban instalado"
    OK=$((OK+1))
fi

# -----------------------------------------------------------------------------
# 9.2 — Configurar jail.local
# -----------------------------------------------------------------------------
echo ""
echo ">>> [2/3] Configurando /etc/fail2ban/jail.local"
echo "    Justificación: jail.local sobreescribe la config por defecto"
echo "    de fail2ban sin tocar jail.conf (que se sobrescribe al"
echo "    actualizar el paquete). Parámetros clave:"
echo "      • bantime  = 3600  → bloqueo de 1 hora"
echo "      • findtime = 600   → ventana de detección de 10 min"
echo "      • maxretry = 5     → 5 intentos antes de banear"
echo "      • backend  = systemd → leer del journal (más robusto)"
echo "      • banaction = nftables-multiport → usa nuestro firewall"
echo ""

JAIL_LOCAL="/etc/fail2ban/jail.local"

if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [DRY-RUN] Escribir $JAIL_LOCAL con jails [sshd] (+ apache si aplica)"
else
    # Backup previo si existe configuración previa
    [[ -f "$JAIL_LOCAL" && ! -f "${JAIL_LOCAL}.pre-hardening" ]] && cp "$JAIL_LOCAL" "${JAIL_LOCAL}.pre-hardening"

    cat > "$JAIL_LOCAL" << 'EOF'
# /etc/fail2ban/jail.local — Configuración endurecida

[DEFAULT]
# Backend: leer logs desde systemd journal (más confiable que tail de archivo)
backend = systemd

# Acción de baneo: usar nftables (integrado con nuestro firewall)
banaction = nftables-multiport
banaction_allports = nftables-allports

# Política general
bantime  = 3600         # 1 hora de baneo
findtime = 600          # Ventana de detección: 10 minutos
maxretry = 5            # 5 intentos fallidos = ban

# IPs que NUNCA serán baneadas (agregar IPs de confianza)
ignoreip = 127.0.0.1/8 ::1

# -----------------------------------------------------------
# Jail para SSH — el más importante
# -----------------------------------------------------------
[sshd]
enabled  = true
port     = ssh
filter   = sshd
maxretry = 5
bantime  = 3600
EOF

    # Si hay Apache, agregamos jails adicionales
    if dpkg -l apache2 2>/dev/null | grep -q "^ii"; then
        cat >> "$JAIL_LOCAL" << 'EOF'

# -----------------------------------------------------------
# Jails de Apache (solo si Apache está instalado)
# -----------------------------------------------------------
[apache-auth]
enabled = true
port    = http,https
filter  = apache-auth
logpath = /var/log/apache2/*error.log
maxretry = 5

[apache-badbots]
enabled = true
port    = http,https
filter  = apache-badbots
logpath = /var/log/apache2/*access.log
maxretry = 2

[apache-noscript]
enabled = true
port    = http,https
filter  = apache-noscript
logpath = /var/log/apache2/*error.log
maxretry = 5
EOF
        echo "    [OK] Apache detectado → jails apache-* agregados"
        OK=$((OK+1))
    fi
fi

echo "    [OK] $JAIL_LOCAL escrito con jail [sshd]"
OK=$((OK+1))

# -----------------------------------------------------------------------------
# 9.3 — Habilitar y verificar
# -----------------------------------------------------------------------------
echo ""
echo ">>> [3/3] Habilitando fail2ban y verificando estado"
echo ""

run "systemctl enable fail2ban"
run "systemctl restart fail2ban"

if [[ $DRY_RUN -eq 0 ]]; then
    # Dar un par de segundos para que arranque
    sleep 2
    if systemctl is-active --quiet fail2ban; then
        echo "    [OK] fail2ban activo"
        OK=$((OK+1))

        # Mostrar jails activos
        echo ""
        echo "    Jails activos:"
        fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/^/      /'
    else
        echo "    [ERROR] fail2ban no arrancó — revisar journalctl -u fail2ban"
        ERR=$((ERR+1))
    fi
else
    echo "  [DRY-RUN] systemctl restart fail2ban && fail2ban-client status"
fi

echo ""
echo "─── Resumen 09_fail2ban.sh ────────────────────────────────"
echo "    OK: $OK   WARN: $WARN   ERR: $ERR"
echo ""

export SCRIPT_OK=$OK SCRIPT_WARN=$WARN SCRIPT_ERR=$ERR
