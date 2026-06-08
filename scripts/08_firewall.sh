#!/bin/bash
# =============================================================================
# 08_firewall.sh — Firewall con nftables
# -----------------------------------------------------------------------------
# QUÉ HACE ESTE SCRIPT:
#   1. Instala nftables (reemplazo moderno de iptables, integrado al kernel).
#   2. Desactiva UFW si estaba activo, para evitar conflictos.
#   3. Aplica una política "deny by default":
#        - Por defecto se DESCARTA todo el tráfico entrante.
#        - Solo se permite explícitamente lo que necesitamos (SSH, loopback,
#          tráfico ya establecido).
#   4. VALIDA la sintaxis con 'nft -c' antes de aplicar — si hay un error,
#      no se carga (evita quedar sin firewall ni con un firewall roto).
# =============================================================================

[[ $EUID -ne 0 ]] && { echo "Ejecutar como root"; exit 1; }
DRY_RUN=${DRY_RUN:-0}
OK=0; WARN=0; ERR=0

run() {
    [[ $DRY_RUN -eq 1 ]] && echo "  [DRY-RUN] $*" || eval "$@"
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " 08_firewall.sh — Firewall nftables (deny by default)"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo " Objetivo: filtrar tráfico de red con política restrictiva."
echo " 'Deny by default' = bloquear TODO excepto lo explícitamente"
echo " permitido. Es el opuesto a 'permitir todo y bloquear malos',"
echo " y es la única estrategia segura."
echo ""

# -----------------------------------------------------------------------------
# 8.1 — Instalar nftables y desactivar UFW
# -----------------------------------------------------------------------------
echo ">>> [1/3] Instalando nftables y deshabilitando UFW"
echo "    Justificación: nftables es el reemplazo oficial de iptables"
echo "    en Linux moderno. Más simple, más rápido. UFW usa iptables"
echo "    por detrás, así que conviene tener solo uno activo."
echo ""

if ! dpkg -l nftables 2>/dev/null | grep -q "^ii"; then
    run "apt-get install -y nftables"
    echo "    [OK] nftables instalado"
    OK=$((OK+1))
else
    echo "    [OK] nftables ya estaba instalado"
    OK=$((OK+1))
fi

# Desactivar UFW para evitar conflictos
if systemctl is-active --quiet ufw 2>/dev/null; then
    run "ufw --force disable"
    run "systemctl disable ufw"
    echo "    [OK] UFW desactivado (usamos nftables directamente)"
    OK=$((OK+1))
fi

# -----------------------------------------------------------------------------
# 8.2 — Escribir reglas
# -----------------------------------------------------------------------------
echo ""
echo ">>> [2/3] Generando reglas de firewall"
echo "    Política aplicada:"
echo "      • input  → DROP (denegar todo lo entrante por defecto)"
echo "      • forward → DROP (no somos router)"
echo "      • output → ACCEPT (permitir saliente)"
echo ""
echo "    Excepciones permitidas en input:"
echo "      • Tráfico ya establecido (ct state established,related)"
echo "      • Loopback (lo)"
echo "      • SSH (tcp/22)"
echo "      • ICMP con rate-limit (4/s) para permitir ping sin abusos"
echo ""

NFT_CONF="/etc/nftables.conf"
if [[ -f "$NFT_CONF" && ! -f "${NFT_CONF}.pre-hardening" ]]; then
    run "cp $NFT_CONF ${NFT_CONF}.pre-hardening"
fi

if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [DRY-RUN] Escribir $NFT_CONF con reglas deny-by-default"
else
    cat > "$NFT_CONF" << 'EOF'
#!/usr/sbin/nft -f
# /etc/nftables.conf — Firewall con política deny-by-default

flush ruleset

table inet filter {

    # --- Tráfico entrante (política: descartar) ---
    chain input {
        type filter hook input priority 0; policy drop;

        # Permitir tráfico de conexiones ya establecidas
        ct state established,related accept

        # Permitir loopback
        iif "lo" accept

        # Descartar paquetes inválidos
        ct state invalid drop

        # ICMP con rate-limit (evita flood, permite ping normal)
        ip  protocol icmp   icmp   type echo-request limit rate 4/second accept
        ip6 nexthdr  icmpv6 icmpv6 type echo-request limit rate 4/second accept

        # ICMPv6 necesario para IPv6 (NDP)
        ip6 nexthdr icmpv6 icmpv6 type { nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept

        # SSH (modificar puerto si se cambió en 05_ssh.sh)
        tcp dport 22 ct state new accept

        # Descomentar si hay servidor web:
        # tcp dport { 80, 443 } ct state new accept
    }

    # --- Reenvío (política: descartar — no somos router) ---
    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    # --- Tráfico saliente (política: aceptar) ---
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
fi
echo "    [OK] $NFT_CONF generado"
OK=$((OK+1))

# -----------------------------------------------------------------------------
# 8.3 — Validar y aplicar
# -----------------------------------------------------------------------------
echo ""
echo ">>> [3/3] Validando sintaxis con 'nft -c' y activando"
echo "    Justificación: 'nft -c' verifica la sintaxis SIN cargar."
echo "    Si hay errores, no aplicamos — preferimos un firewall"
echo "    inalterado a uno roto que no filtra nada."
echo ""

if [[ $DRY_RUN -eq 0 ]]; then
    if nft -c -f "$NFT_CONF" 2>/dev/null; then
        echo "    [OK] Sintaxis de nftables válida"
        OK=$((OK+1))
        run "systemctl enable nftables"
        run "systemctl restart nftables"
        echo "    [OK] nftables activo con política deny-by-default"
        OK=$((OK+1))

        # Mostrar reglas aplicadas
        echo ""
        echo "    Reglas activas (primeras líneas):"
        nft list ruleset 2>/dev/null | head -25 | sed 's/^/      /'
    else
        echo "    [ERROR] Sintaxis inválida — no se aplican las reglas"
        ERR=$((ERR+1))
    fi
else
    echo "  [DRY-RUN] nft -c -f $NFT_CONF && systemctl restart nftables"
fi

echo ""
echo "─── Resumen 08_firewall.sh ────────────────────────────────"
echo "    OK: $OK   WARN: $WARN   ERR: $ERR"
echo ""

export SCRIPT_OK=$OK SCRIPT_WARN=$WARN SCRIPT_ERR=$ERR
