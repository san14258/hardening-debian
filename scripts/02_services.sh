#!/bin/bash
# =============================================================================
# 02_services.sh — CIS Sección 2.x
# -----------------------------------------------------------------------------
# QUÉ HACE ESTE SCRIPT:
#   1. Deshabilita servicios de red que no se usan en un servidor típico
#      (avahi, cups, NFS, Samba, SNMP, etc.). Cada servicio que escucha
#      en un puerto es una potencial puerta de entrada.
#   2. Elimina paquetes inseguros que transmiten datos sin cifrar
#      (telnet, rsh, talk, nis) — estos protocolos son legacy y nunca
#      deberían estar instalados en un sistema moderno.
#   3. Muestra qué servicios quedan escuchando en la red para revisión.
# =============================================================================

[[ $EUID -ne 0 ]] && { echo "Ejecutar como root"; exit 1; }
DRY_RUN=${DRY_RUN:-0}
OK=0; WARN=0; ERR=0

run() {
    [[ $DRY_RUN -eq 1 ]] && echo "  [DRY-RUN] $*" || eval "$@"
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " 02_services.sh — CIS 2.x — Servicios innecesarios"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo " Objetivo: reducir la superficie de ataque deshabilitando"
echo " servicios de red que no son necesarios y eliminando"
echo " paquetes con protocolos inseguros (telnet, rsh, etc.)."
echo ""

# -----------------------------------------------------------------------------
# 2.1 — Servicios a deshabilitar
# -----------------------------------------------------------------------------
echo ">>> [1/3] Deshabilitando servicios de red innecesarios"
echo "    Justificación: avahi, cups, NFS, etc. abren puertos que un"
echo "    atacante puede escanear y explotar. Si no los necesitamos,"
echo "    los detenemos y desactivamos para que no arranquen al boot."
echo ""

SERVICES=(
    "avahi-daemon:Zeroconf/Bonjour (descubrimiento red local)"
    "cups:Sistema de impresión"
    "isc-dhcp-server:Servidor DHCP"
    "slapd:Servidor LDAP"
    "nfs-server:Servidor NFS"
    "rpcbind:Mapeador RPC (requerido solo por NFS)"
    "bind9:Servidor DNS"
    "vsftpd:Servidor FTP"
    "dovecot:Servidor IMAP/POP3"
    "smbd:Samba (compartir archivos Windows)"
    "snmpd:Agente SNMP"
    "bluetooth:Servicio Bluetooth"
)

for entry in "${SERVICES[@]}"; do
    svc="${entry%%:*}"
    desc="${entry##*:}"

    if systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${svc}"; then
        if systemctl is-active --quiet "$svc"; then
            run "systemctl stop $svc"
            run "systemctl disable $svc"
            echo "    [OK] $svc detenido y deshabilitado — $desc"
            OK=$((OK+1))
        else
            run "systemctl disable $svc 2>/dev/null || true"
            echo "    [OK] $svc ya estaba inactivo — $desc"
            OK=$((OK+1))
        fi
    fi
done

# -----------------------------------------------------------------------------
# 2.2 — Paquetes inseguros a eliminar
# -----------------------------------------------------------------------------
echo ""
echo ">>> [2/3] Eliminando paquetes con protocolos inseguros"
echo "    Justificación: telnet, rsh y talk transmiten TODO en texto"
echo "    plano, incluyendo contraseñas. Cualquier sniffer en la red"
echo "    puede capturarlas. SSH los reemplaza con cifrado."
echo ""

PACKAGES=(
    "telnet:Protocolo de acceso remoto SIN cifrado"
    "rsh-client:Shell remota SIN cifrado"
    "talk:Chat por terminal SIN cifrado"
    "nis:Network Information Service — legacy inseguro"
    "xinetd:Super-servidor de servicios de red legacy"
)

for entry in "${PACKAGES[@]}"; do
    pkg="${entry%%:*}"
    desc="${entry##*:}"
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        run "apt-get remove --purge -y $pkg"
        echo "    [OK] $pkg eliminado — $desc"
        OK=$((OK+1))
    else
        echo "    [OK] $pkg no estaba instalado — $desc"
        OK=$((OK+1))
    fi
done

# -----------------------------------------------------------------------------
# 2.3 — Mostrar puertos abiertos para revisión manual
# -----------------------------------------------------------------------------
echo ""
echo ">>> [3/3] Verificando puertos abiertos restantes"
echo "    Justificación: después de deshabilitar servicios, revisamos"
echo "    qué sigue escuchando en la red. Cualquier puerto inesperado"
echo "    aquí merece investigación."
echo ""

if [[ $DRY_RUN -eq 0 ]]; then
    echo "    Puertos en escucha (excluyendo localhost):"
    ss -tlnp 2>/dev/null | grep -vE "127\.0\.0\.1|::1" | tail -n +2 | while read -r line; do
        echo "    → $line"
    done
fi

echo ""
echo "─── Resumen 02_services.sh ────────────────────────────────"
echo "    OK: $OK   WARN: $WARN   ERR: $ERR"
echo ""

export SCRIPT_OK=$OK SCRIPT_WARN=$WARN SCRIPT_ERR=$ERR
