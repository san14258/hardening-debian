#!/bin/bash
# =============================================================================
# 01_filesystem.sh — CIS Sección 1.x
# -----------------------------------------------------------------------------
# QUÉ HACE ESTE SCRIPT:
#   1. Deshabilita módulos del kernel para sistemas de archivos poco comunes
#      (cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf). Si nadie los
#      usa pero están cargables, son superficie de ataque innecesaria.
#   2. Verifica que las particiones temporales (/tmp, /var/tmp, /dev/shm)
#      tengan las opciones nodev, nosuid y noexec — esto impide que un
#      atacante ejecute binarios o cree dispositivos en directorios donde
#      cualquier usuario puede escribir.
#   3. Ajusta permisos de archivos críticos (/etc/passwd, /etc/shadow, etc.)
#      a los valores recomendados por CIS.
#   4. Configura UMASK 027 en /etc/login.defs — los archivos nuevos no son
#      legibles por "otros" usuarios por defecto.
# =============================================================================

[[ $EUID -ne 0 ]] && { echo "Ejecutar como root"; exit 1; }
DRY_RUN=${DRY_RUN:-0}
OK=0; WARN=0; ERR=0

# Función para ejecutar comandos respetando el modo dry-run
run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  [DRY-RUN] $*"
    else
        eval "$@"
    fi
}

# Banner explicativo del script
echo ""
echo "═══════════════════════════════════════════════════════════"
echo " 01_filesystem.sh — CIS 1.x — Filesystem y módulos kernel"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo " Objetivo: reducir la superficie de ataque del sistema de"
echo " archivos. Deshabilitamos módulos del kernel innecesarios,"
echo " endurecemos las opciones de montaje de particiones"
echo " temporales y ajustamos permisos de archivos sensibles."
echo ""

# -----------------------------------------------------------------------------
# 1.1 — Deshabilitar módulos de filesystem no usados
# -----------------------------------------------------------------------------
echo ">>> [1/4] Deshabilitando módulos de filesystem innecesarios"
echo "    Justificación: cada módulo cargable es código que un atacante"
echo "    podría aprovechar. Si no usamos cramfs/squashfs/etc., los bloqueamos."
echo ""

MODULES=(cramfs freevxfs jffs2 hfs hfsplus squashfs udf)
for mod in "${MODULES[@]}"; do
    CONF="/etc/modprobe.d/cis-${mod}.conf"
    if [[ -f "$CONF" ]]; then
        echo "    [OK] Módulo $mod ya estaba deshabilitado"
        OK=$((OK+1))
    else
        run "echo 'install $mod /bin/true' > $CONF"
        run "echo 'blacklist $mod' >> $CONF"
        echo "    [OK] Módulo $mod deshabilitado → $CONF"
        OK=$((OK+1))
    fi
done

# -----------------------------------------------------------------------------
# 1.2 — Verificar opciones de montaje en particiones temporales
# -----------------------------------------------------------------------------
echo ""
echo ">>> [2/4] Verificando opciones de montaje en particiones temporales"
echo "    Justificación: /tmp, /var/tmp y /dev/shm son escribibles por"
echo "    cualquier usuario. Con nodev/nosuid/noexec evitamos que un"
echo "    atacante ejecute malware o eleve privilegios desde ahí."
echo ""

for mp in /tmp /var/tmp /dev/shm; do
    OPTS=$(findmnt -n -o OPTIONS "$mp" 2>/dev/null)
    if [[ -z "$OPTS" ]]; then
        echo "    [WARN] $mp no es una partición separada — considerar agregarla en /etc/fstab"
        WARN=$((WARN+1))
        continue
    fi
    for opt in nodev nosuid noexec; do
        if echo "$OPTS" | grep -q "$opt"; then
            echo "    [OK] $mp tiene opción $opt"
            OK=$((OK+1))
        else
            echo "    [WARN] $mp NO tiene opción $opt (agregar en /etc/fstab)"
            WARN=$((WARN+1))
        fi
    done
done

# -----------------------------------------------------------------------------
# 1.3 — Permisos de archivos críticos del sistema
# -----------------------------------------------------------------------------
echo ""
echo ">>> [3/4] Ajustando permisos de archivos críticos"
echo "    Justificación: /etc/shadow contiene los hashes de contraseñas."
echo "    Si fuera legible por cualquiera, se podrían atacar offline con"
echo "    hashcat o John the Ripper. Los permisos deben ser estrictos."
echo ""

fix_perm() {
    local file=$1 perm=$2 owner=$3 group=$4
    if [[ ! -f "$file" ]]; then
        echo "    [WARN] $file no existe"
        WARN=$((WARN+1))
        return
    fi
    run "chmod $perm $file"
    run "chown $owner:$group $file"
    echo "    [OK] $file → $perm $owner:$group"
    OK=$((OK+1))
}

fix_perm /etc/passwd          644 root root
fix_perm /etc/shadow          640 root shadow
fix_perm /etc/group           644 root root
fix_perm /etc/gshadow         640 root shadow
fix_perm /etc/ssh/sshd_config 600 root root
[[ -f /boot/grub/grub.cfg ]] && fix_perm /boot/grub/grub.cfg 600 root root

# -----------------------------------------------------------------------------
# 1.4 — UMASK 027 en login.defs
# -----------------------------------------------------------------------------
echo ""
echo ">>> [4/4] Configurando UMASK 027 en /etc/login.defs"
echo "    Justificación: UMASK 027 hace que los archivos nuevos NO sean"
echo "    legibles ni accesibles por 'otros' usuarios por defecto."
echo "    Es el comportamiento recomendado por CIS para servidores."
echo ""

if grep -qE "^UMASK\s+027" /etc/login.defs 2>/dev/null; then
    echo "    [OK] UMASK 027 ya estaba configurado"
    OK=$((OK+1))
else
    run "cp /etc/login.defs /etc/login.defs.orig 2>/dev/null"
    run "sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs"
    grep -q "^UMASK" /etc/login.defs || run "echo 'UMASK\t\t027' >> /etc/login.defs"
    echo "    [OK] UMASK configurado en 027"
    OK=$((OK+1))
fi

# También políticas básicas de expiración en login.defs (relacionadas)
echo ""
echo "    Configurando políticas básicas de expiración de contraseñas:"
run "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs"
run "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs"
run "sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t14/' /etc/login.defs"
echo "    [OK] PASS_MAX_DAYS=90, PASS_MIN_DAYS=7, PASS_WARN_AGE=14"
OK=$((OK+1))

# -----------------------------------------------------------------------------
# Resumen del script
# -----------------------------------------------------------------------------
echo ""
echo "─── Resumen 01_filesystem.sh ──────────────────────────────"
echo "    OK: $OK   WARN: $WARN   ERR: $ERR"
echo ""

# Exportar contadores para que el main los sume al total global
export SCRIPT_OK=$OK SCRIPT_WARN=$WARN SCRIPT_ERR=$ERR
