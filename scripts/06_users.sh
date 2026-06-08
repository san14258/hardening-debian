#!/bin/bash
# =============================================================================
# 06_users.sh — CIS Sección 5.4
# -----------------------------------------------------------------------------
# QUÉ HACE ESTE SCRIPT:
#   1. Detecta cuentas con UID 0 distintas de root — solo root debería
#      tener UID 0; cualquier otra cuenta con ese UID es una puerta trasera.
#   2. Bloquea cuentas con contraseña vacía — son acceso libre al sistema.
#   3. Cambia el shell de cuentas de sistema (UID<1000) a /usr/sbin/nologin
#      para que nadie pueda hacer login con esas cuentas técnicas.
#   4. Configura sudo: timeout de 15 min, logging, sintaxis validada.
#   5. Configura variables de entorno con TMOUT=900 (cierra sesiones
#      inactivas en bash) y HISTTIMEFORMAT (timestamps en el historial).
# =============================================================================

[[ $EUID -ne 0 ]] && { echo "Ejecutar como root"; exit 1; }
DRY_RUN=${DRY_RUN:-0}
OK=0; WARN=0; ERR=0

run() {
    [[ $DRY_RUN -eq 1 ]] && echo "  [DRY-RUN] $*" || eval "$@"
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " 06_users.sh — CIS 5.4 — Usuarios y privilegios"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo " Objetivo: asegurar el control de acceso al sistema."
echo " Detectar cuentas anómalas, bloquear las inseguras y"
echo " endurecer la configuración de sudo."
echo ""

# -----------------------------------------------------------------------------
# 6.1 — UID 0 distintos de root
# -----------------------------------------------------------------------------
echo ">>> [1/4] Verificando que solo root tenga UID 0"
echo "    Justificación: UID 0 = superusuario. Si hay una cuenta 'oculta'"
echo "    con UID 0 (típica técnica de persistencia tras un compromiso),"
echo "    el atacante tiene root permanente. SOLO root debe tener UID 0."
echo ""

UID0_USERS=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
for user in $UID0_USERS; do
    if [[ "$user" == "root" ]]; then
        echo "    [OK] root tiene UID 0 (correcto)"
        OK=$((OK+1))
    else
        echo "    [ERROR] Usuario '$user' tiene UID 0 → INVESTIGAR INMEDIATAMENTE"
        ERR=$((ERR+1))
    fi
done

# -----------------------------------------------------------------------------
# 6.2 — Cuentas con password vacío
# -----------------------------------------------------------------------------
echo ""
echo ">>> [2/4] Bloqueando cuentas con contraseña vacía"
echo "    Justificación: una cuenta sin contraseña es acceso libre."
echo "    'passwd -l' las bloquea sin eliminarlas (preserva datos)."
echo ""

EMPTY_FOUND=0
while IFS=: read -r user pass _; do
    if [[ -z "$pass" ]]; then
        echo "    [ERROR] Cuenta '$user' sin contraseña → bloqueando"
        run "passwd -l $user"
        ERR=$((ERR+1))
        EMPTY_FOUND=1
    fi
done < /etc/shadow

if [[ $EMPTY_FOUND -eq 0 ]]; then
    echo "    [OK] Ninguna cuenta tiene contraseña vacía"
    OK=$((OK+1))
fi

# -----------------------------------------------------------------------------
# 6.3 — Shells de cuentas de sistema
# -----------------------------------------------------------------------------
echo ""
echo ">>> [3/4] Asegurando que cuentas de sistema no puedan hacer login"
echo "    Justificación: cuentas como 'www-data', 'mysql', 'redis' existen"
echo "    para ejecutar servicios, NO para que nadie haga login con ellas."
echo "    Cambiando su shell a /usr/sbin/nologin evitamos que un atacante"
echo "    que comprometa esas cuentas pueda obtener una shell interactiva."
echo ""

NOLOGIN="/usr/sbin/nologin"
while IFS=: read -r user _ uid _ _ _ shell; do
    if [[ "$uid" -gt 0 && "$uid" -lt 1000 \
          && "$shell" != "$NOLOGIN" && "$shell" != "/bin/false" \
          && "$shell" != "/usr/bin/false" ]]; then
        echo "    [WARN] '$user' (UID $uid) tiene shell '$shell' → cambiando a nologin"
        run "usermod -s $NOLOGIN $user"
        WARN=$((WARN+1))
    fi
done < /etc/passwd

# -----------------------------------------------------------------------------
# 6.4 — Configuración de sudo y entorno
# -----------------------------------------------------------------------------
echo ""
echo ">>> [4/4] Endureciendo sudo y variables de entorno"
echo "    Justificación: sudo debe registrar todo lo que se ejecuta y"
echo "    debe pedir contraseña frecuentemente. TMOUT=900 cierra"
echo "    automáticamente sesiones inactivas tras 15 minutos."
echo ""

# Asegurar sudo instalado
if ! dpkg -l sudo 2>/dev/null | grep -q "^ii"; then
    run "apt-get install -y sudo"
    echo "    [OK] sudo instalado"
    OK=$((OK+1))
fi

# Configuración endurecida de sudo
SUDO_HARDENING="/etc/sudoers.d/cis-hardening"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [DRY-RUN] Crear $SUDO_HARDENING con timeout, logfile, requiretty"
else
    cat > "$SUDO_HARDENING" << 'EOF'
# Endurecimiento de sudo — CIS 5.3
Defaults timestamp_timeout=15
Defaults logfile=/var/log/sudo.log
Defaults !visiblepw
Defaults use_pty
EOF
    chmod 440 "$SUDO_HARDENING"
    # Validar sintaxis ANTES de dejarlo activo
    if ! visudo -c -f "$SUDO_HARDENING" >/dev/null 2>&1; then
        echo "    [ERROR] Sintaxis inválida en $SUDO_HARDENING → eliminando"
        rm -f "$SUDO_HARDENING"
        ERR=$((ERR+1))
    else
        echo "    [OK] sudo: timeout 15 min, logfile activo, use_pty"
        OK=$((OK+1))
    fi
fi

# Variables de entorno
PROFILE="/etc/profile.d/cis-hardening.sh"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [DRY-RUN] Crear $PROFILE con TMOUT y HISTTIMEFORMAT"
else
    cat > "$PROFILE" << 'EOF'
# Hardening CIS — variables de entorno del shell
readonly TMOUT=900            # Cierra sesión inactiva tras 15 min
readonly HISTSIZE=1000
readonly HISTFILESIZE=2000
readonly HISTTIMEFORMAT='%F %T '   # Timestamps en el historial
EOF
    chmod 644 "$PROFILE"
fi
echo "    [OK] TMOUT=900 y HISTTIMEFORMAT configurados en $PROFILE"
OK=$((OK+1))

echo ""
echo "─── Resumen 06_users.sh ───────────────────────────────────"
echo "    OK: $OK   WARN: $WARN   ERR: $ERR"
echo ""

export SCRIPT_OK=$OK SCRIPT_WARN=$WARN SCRIPT_ERR=$ERR
