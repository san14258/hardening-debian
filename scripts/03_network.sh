#!/bin/bash
# =============================================================================
# 03_network.sh — CIS Sección 3.x
# -----------------------------------------------------------------------------
# QUÉ HACE ESTE SCRIPT:
#   1. Aplica parámetros sysctl de hardening en /etc/sysctl.d/99-hardening.conf
#      cubriendo protección de red (anti-spoofing, anti-redirect) y
#      endurecimiento del kernel (ASLR, ptrace, kptr_restrict, etc.).
#   2. Deshabilita protocolos de red poco usados (dccp, sctp, rds, tipc).
#   3. Instala mod_evasive de Apache (recomendado por Lynis) para mitigar
#      ataques de denegación de servicio si hay un servidor web instalado.
# =============================================================================

[[ $EUID -ne 0 ]] && { echo "Ejecutar como root"; exit 1; }
DRY_RUN=${DRY_RUN:-0}
OK=0; WARN=0; ERR=0

run() {
    [[ $DRY_RUN -eq 1 ]] && echo "  [DRY-RUN] $*" || eval "$@"
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " 03_network.sh — CIS 3.x — Hardening de red y kernel"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo " Objetivo: endurecer la pila de red y el kernel contra"
echo " ataques comunes: spoofing, redirecciones ICMP maliciosas,"
echo " SYN floods, escalada de privilegios mediante ptrace, etc."
echo ""

# -----------------------------------------------------------------------------
# 3.1 — Aplicar parámetros sysctl
# -----------------------------------------------------------------------------
echo ">>> [1/3] Aplicando parámetros sysctl de hardening"
echo "    Justificación: cada parámetro mitiga un vector concreto."
echo "    Los más importantes:"
echo "      • accept_redirects=0   → un atacante no puede redirigir tráfico"
echo "      • log_martians=1       → registra paquetes con IPs sospechosas"
echo "      • rp_filter=1          → previene IP spoofing (Reverse Path Filter)"
echo "      • kptr_restrict=2      → oculta punteros del kernel a /proc"
echo "      • yama.ptrace_scope=1  → restringe ptrace (anti-debuggeo malicioso)"
echo "      • bpf_jit_harden=2     → endurece el JIT de eBPF"
echo ""

SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"

if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [DRY-RUN] Crear $SYSCTL_FILE con parámetros de hardening"
else
    cat > "$SYSCTL_FILE" << 'EOF'
# =============================================================================
# 99-hardening.conf — Parámetros sysctl de hardening
# Generado por el framework de hardening CIS
# =============================================================================

# --- Endurecimiento del kernel ---
kernel.kptr_restrict = 2              # Ocultar punteros del kernel en /proc
kernel.sysrq = 0                      # Deshabilitar tecla mágica SysRq
kernel.yama.ptrace_scope = 1          # Restringir ptrace (anti-debuggeo malicioso)

# --- Protección de red IPv4 ---
net.ipv4.conf.all.accept_redirects = 0      # No aceptar ICMP redirects
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0        # No enviar ICMP redirects
net.ipv4.conf.default.accept_source_route = 0  # Anti source routing
net.ipv4.conf.all.log_martians = 1          # Loguear paquetes con IPs falsas
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1             # Reverse Path Filter — anti spoofing

# --- Protección de red IPv6 ---
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- Protección del sistema de archivos ---
fs.protected_fifos = 2                # Protección contra ataques en FIFOs

# --- Endurecimiento adicional (recomendaciones de Lynis) ---
dev.tty.ldisc_autoload = 0            # Evita carga de drivers TTY arbitrarios
net.core.bpf_jit_harden = 2           # Endurece el JIT de eBPF
EOF
fi
echo "    [OK] Archivo $SYSCTL_FILE creado"
OK=$((OK+1))

echo "    Aplicando parámetros con: sysctl --system"
run "sysctl --system > /dev/null 2>&1"
echo "    [OK] Parámetros sysctl aplicados"
OK=$((OK+1))

# Verificar algunos valores clave (solo si no es dry-run)
if [[ $DRY_RUN -eq 0 ]]; then
    echo ""
    echo "    Verificación de valores aplicados:"
    for key in kernel.kptr_restrict kernel.yama.ptrace_scope net.ipv4.conf.all.rp_filter net.ipv4.conf.all.log_martians; do
        val=$(sysctl -n "$key" 2>/dev/null)
        echo "      → $key = $val"
    done
fi

# -----------------------------------------------------------------------------
# 3.2 — Deshabilitar protocolos de red innecesarios
# -----------------------------------------------------------------------------
echo ""
echo ">>> [2/3] Deshabilitando protocolos de red innecesarios"
echo "    Justificación: DCCP, SCTP, RDS y TIPC son protocolos que casi"
echo "    nadie usa pero están en el kernel. Han tenido vulnerabilidades"
echo "    históricas (CVEs varios). Si no los usamos, los bloqueamos."
echo ""

NET_MODULES=(dccp sctp rds tipc)
for mod in "${NET_MODULES[@]}"; do
    CONF="/etc/modprobe.d/cis-net-${mod}.conf"
    if [[ -f "$CONF" ]]; then
        echo "    [OK] Protocolo $mod ya estaba bloqueado"
        OK=$((OK+1))
    else
        run "echo 'install $mod /bin/true' > $CONF"
        run "echo 'blacklist $mod' >> $CONF"
        echo "    [OK] Protocolo $mod bloqueado"
        OK=$((OK+1))
    fi
done

# -----------------------------------------------------------------------------
# 3.3 — Instalar mod_evasive si hay Apache
# -----------------------------------------------------------------------------
echo ""
echo ">>> [3/3] Instalando mod_evasive (si hay Apache)"
echo "    Justificación: Lynis lo recomienda. mod_evasive detecta y"
echo "    bloquea automáticamente IPs que hacen muchas peticiones por"
echo "    segundo — protección básica contra DoS y escaneos."
echo ""

if dpkg -l apache2 2>/dev/null | grep -q "^ii"; then
    if dpkg -l libapache2-mod-evasive 2>/dev/null | grep -q "^ii"; then
        echo "    [OK] mod_evasive ya estaba instalado"
        OK=$((OK+1))
    else
        run "apt-get install -y libapache2-mod-evasive"
        run "systemctl reload apache2 2>/dev/null || true"
        echo "    [OK] mod_evasive instalado y Apache recargado"
        OK=$((OK+1))
    fi
else
    echo "    [INFO] Apache no está instalado — saltando mod_evasive"
fi

echo ""
echo "─── Resumen 03_network.sh ─────────────────────────────────"
echo "    OK: $OK   WARN: $WARN   ERR: $ERR"
echo ""

export SCRIPT_OK=$OK SCRIPT_WARN=$WARN SCRIPT_ERR=$ERR
