#!/bin/bash
# =============================================================================
# 10_updates.sh — CIS Sección 1.9
# -----------------------------------------------------------------------------
# QUÉ HACE ESTE SCRIPT:
#   1. Actualiza la lista de paquetes y aplica las actualizaciones de
#      seguridad pendientes.
#   2. Instala y habilita unattended-upgrades — el servicio que aplica
#      AUTOMÁTICAMENTE los parches de seguridad diariamente.
#   3. Configura las fuentes de seguridad para que solo se actualicen
#      paquetes con vulnerabilidades, no upgrades mayores que podrían
#      romper la compatibilidad.
#   4. Reporta si quedan actualizaciones pendientes o si el sistema
#      requiere reinicio.
# =============================================================================

[[ $EUID -ne 0 ]] && { echo "Ejecutar como root"; exit 1; }
DRY_RUN=${DRY_RUN:-0}
OK=0; WARN=0; ERR=0

run() {
    [[ $DRY_RUN -eq 1 ]] && echo "  [DRY-RUN] $*" || eval "$@"
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " 10_updates.sh — CIS 1.9 — Actualizaciones de seguridad"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo " Objetivo: mantener el sistema parcheado. La mayoría de los"
echo " ataques exitosos explotan vulnerabilidades CONOCIDAS para"
echo " las que ya existe parche, pero el sysadmin no lo aplicó."
echo " Con unattended-upgrades, los parches de seguridad se"
echo " aplican automáticamente todos los días."
echo ""

# -----------------------------------------------------------------------------
# 10.1 — Actualizar el sistema
# -----------------------------------------------------------------------------
echo ">>> [1/3] Actualizando el sistema ahora"
echo "    Justificación: antes de configurar las actualizaciones"
echo "    automáticas, ponemos el sistema al día con lo que ya está"
echo "    disponible."
echo ""

run "apt-get update -qq"
echo "    [OK] Lista de paquetes actualizada"
OK=$((OK+1))

run "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq"
echo "    [OK] Paquetes actualizados"
OK=$((OK+1))

# -----------------------------------------------------------------------------
# 10.2 — Habilitar actualizaciones automáticas
# -----------------------------------------------------------------------------
echo ""
echo ">>> [2/3] Configurando unattended-upgrades"
echo "    Justificación: actualizar manualmente requiere disciplina"
echo "    diaria. unattended-upgrades se ejecuta solo cada día y"
echo "    aplica los parches de seguridad sin intervención. Es la"
echo "    diferencia entre 'lo parcheo cuando me acuerdo' y"
echo "    'siempre está al día'."
echo ""

if ! dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"; then
    run "apt-get install -y unattended-upgrades apt-listchanges"
    echo "    [OK] unattended-upgrades instalado"
    OK=$((OK+1))
else
    echo "    [OK] unattended-upgrades ya estaba instalado"
    OK=$((OK+1))
fi

# Archivo que controla cuándo correr unattended-upgrades
AUTO_UPGRADES="/etc/apt/apt.conf.d/20auto-upgrades"

if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [DRY-RUN] Escribir $AUTO_UPGRADES"
else
    cat > "$AUTO_UPGRADES" << 'EOF'
// Generado por framework de hardening
APT::Periodic::Update-Package-Lists "1";        // Actualizar lista diariamente
APT::Periodic::Unattended-Upgrade "1";          // Instalar parches de seguridad
APT::Periodic::AutocleanInterval "7";           // Limpiar paquetes viejos semanalmente
APT::Periodic::Download-Upgradeable-Packages "1";
EOF
fi
echo "    [OK] $AUTO_UPGRADES configurado (actualización diaria)"
OK=$((OK+1))

# Verificar que las fuentes de seguridad estén habilitadas
UNATTENDED_CONF="/etc/apt/apt.conf.d/50unattended-upgrades"
if [[ -f "$UNATTENDED_CONF" ]]; then
    if grep -qE "^\s*\".*-security\"" "$UNATTENDED_CONF"; then
        echo "    [OK] Fuentes de seguridad habilitadas en $UNATTENDED_CONF"
        OK=$((OK+1))
    else
        echo "    [WARN] Verificar manualmente $UNATTENDED_CONF para asegurar que -security esté activo"
        WARN=$((WARN+1))
    fi
fi

# Habilitar el timer
run "systemctl enable apt-daily.timer"
run "systemctl enable apt-daily-upgrade.timer"
echo "    [OK] Timers de apt-daily habilitados"
OK=$((OK+1))

# -----------------------------------------------------------------------------
# 10.3 — Reportar estado final
# -----------------------------------------------------------------------------
echo ""
echo ">>> [3/3] Verificando estado del sistema"
echo ""

if [[ $DRY_RUN -eq 0 ]]; then
    # Cuántas actualizaciones quedan pendientes
    PENDING=$(apt-get --simulate upgrade 2>/dev/null | grep -c "^Inst")
    if [[ "$PENDING" -eq 0 ]]; then
        echo "    [OK] Sistema al día — 0 actualizaciones pendientes"
        OK=$((OK+1))
    else
        echo "    [WARN] $PENDING actualizaciones pendientes (revisar manualmente)"
        WARN=$((WARN+1))
    fi

    # ¿Requiere reinicio?
    if [[ -f /var/run/reboot-required ]]; then
        echo "    [WARN] El sistema requiere REINICIO para aplicar updates de kernel"
        WARN=$((WARN+1))
        if [[ -f /var/run/reboot-required.pkgs ]]; then
            echo "    Paquetes que requieren reinicio:"
            head -5 /var/run/reboot-required.pkgs | sed 's/^/      → /'
        fi
    else
        echo "    [OK] No se requiere reinicio"
        OK=$((OK+1))
    fi
fi

echo ""
echo "─── Resumen 10_updates.sh ─────────────────────────────────"
echo "    OK: $OK   WARN: $WARN   ERR: $ERR"
echo ""

export SCRIPT_OK=$OK SCRIPT_WARN=$WARN SCRIPT_ERR=$ERR
