#!/bin/bash
# =============================================================================
# 07_pam.sh — CIS Sección 5.3
# -----------------------------------------------------------------------------
# QUÉ HACE ESTE SCRIPT:
#   1. Instala libpam-pwquality y configura una política estricta de
#      contraseñas: 14+ caracteres, con mayúsculas, minúsculas, dígitos
#      y especiales; sin repeticiones; sin estar en diccionario.
#   2. Configura pam_faillock: tras 5 intentos fallidos, la cuenta se
#      bloquea por 15 minutos. Protección contra fuerza bruta local.
#   3. Configura hashing SHA-512 con 10.000 rondas e historial de 5
#      contraseñas (no reutilizar las últimas 5).
#
#   ATENCIÓN: PAM es delicado. Si rompemos common-auth o common-password
#   nadie puede loguearse. Por eso hacemos backup .pre-hardening y
#   verificamos antes de aplicar cambios destructivos.
# =============================================================================

[[ $EUID -ne 0 ]] && { echo "Ejecutar como root"; exit 1; }
DRY_RUN=${DRY_RUN:-0}
OK=0; WARN=0; ERR=0

run() {
    [[ $DRY_RUN -eq 1 ]] && echo "  [DRY-RUN] $*" || eval "$@"
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " 07_pam.sh — CIS 5.3 — PAM y contraseñas"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo " Objetivo: forzar contraseñas robustas y protegerlas contra"
echo " fuerza bruta. PAM (Pluggable Authentication Modules) es el"
echo " framework que controla autenticación en Linux."
echo ""
echo " ATENCIÓN: tocar PAM puede dejar el sistema sin acceso si"
echo " se rompe un archivo. Hacemos backup antes de cada cambio."
echo ""

# -----------------------------------------------------------------------------
# 7.1 — Calidad de contraseñas
# -----------------------------------------------------------------------------
echo ">>> [1/3] Instalando pwquality y aplicando política de contraseñas"
echo "    Justificación: contraseñas débiles son la causa #1 de"
echo "    compromisos. La política exige:"
echo "      • Mínimo 14 caracteres"
echo "      • Las 4 clases: mayúsc / minúsc / dígitos / especiales"
echo "      • No más de 3 caracteres iguales seguidos"
echo "      • No estar en el diccionario de palabras comunes"
echo ""

if ! dpkg -l libpam-pwquality 2>/dev/null | grep -q "^ii"; then
    run "apt-get install -y libpam-pwquality"
    echo "    [OK] libpam-pwquality instalado"
    OK=$((OK+1))
else
    echo "    [OK] libpam-pwquality ya estaba instalado"
    OK=$((OK+1))
fi

PWQ_CONF="/etc/security/pwquality.conf"
if [[ -f "$PWQ_CONF" && ! -f "${PWQ_CONF}.pre-hardening" ]]; then
    run "cp $PWQ_CONF ${PWQ_CONF}.pre-hardening"
fi

if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [DRY-RUN] Escribir $PWQ_CONF con política estricta"
else
    cat > "$PWQ_CONF" << 'EOF'
# Política de contraseñas — CIS 5.3.1
minlen = 14              # Longitud mínima
minclass = 4             # Las 4 clases obligatorias
dcredit = -1             # Al menos 1 dígito
ucredit = -1             # Al menos 1 mayúscula
lcredit = -1             # Al menos 1 minúscula
ocredit = -1             # Al menos 1 carácter especial
maxrepeat = 3            # Sin más de 3 caracteres iguales seguidos
difok = 5                # Mínimo 5 caracteres diferentes a la anterior
dictcheck = 1            # Rechazar palabras de diccionario
enforce_for_root = 1     # Aplicar también a root
EOF
fi
echo "    [OK] Política de contraseñas aplicada en $PWQ_CONF"
OK=$((OK+1))

# -----------------------------------------------------------------------------
# 7.2 — pam_faillock (bloqueo por intentos fallidos)
# -----------------------------------------------------------------------------
echo ""
echo ">>> [2/3] Configurando pam_faillock contra fuerza bruta"
echo "    Justificación: sin esto, un atacante puede probar contraseñas"
echo "    infinitamente. Con faillock, tras 5 intentos fallidos la"
echo "    cuenta se bloquea 15 minutos — la fuerza bruta se vuelve"
echo "    inviable en tiempo razonable."
echo ""

COMMON_AUTH="/etc/pam.d/common-auth"
# Backup si no existe ya
if [[ ! -f "${COMMON_AUTH}.pre-hardening" ]]; then
    run "cp $COMMON_AUTH ${COMMON_AUTH}.pre-hardening"
    echo "    [OK] Backup: ${COMMON_AUTH}.pre-hardening"
    OK=$((OK+1))
fi

if grep -q "pam_faillock" "$COMMON_AUTH" 2>/dev/null; then
    echo "    [OK] pam_faillock ya estaba configurado"
    OK=$((OK+1))
else
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  [DRY-RUN] Insertar pam_faillock en $COMMON_AUTH"
    else
        # Insertar al inicio: preauth (chequeo previo)
        sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=900 fail_interval=900' "$COMMON_AUTH"
        # Agregar al final: authfail (registrar fallo si la auth no pasa)
        echo 'auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900 fail_interval=900' >> "$COMMON_AUTH"
    fi
    echo "    [OK] pam_faillock: 5 intentos → bloqueo 15 min"
    OK=$((OK+1))
fi

# Si existe faillock.conf (sistemas más nuevos), también lo configuramos
FAILLOCK_CONF="/etc/security/faillock.conf"
if [[ -f "$FAILLOCK_CONF" ]]; then
    run "sed -i 's/^# deny.*/deny = 5/' $FAILLOCK_CONF"
    run "sed -i 's/^# unlock_time.*/unlock_time = 900/' $FAILLOCK_CONF"
    run "sed -i 's/^# fail_interval.*/fail_interval = 900/' $FAILLOCK_CONF"
    echo "    [OK] $FAILLOCK_CONF también configurado"
    OK=$((OK+1))
fi

# -----------------------------------------------------------------------------
# 7.3 — Hashing fuerte e historial de contraseñas
# -----------------------------------------------------------------------------
echo ""
echo ">>> [3/3] Configurando hashing SHA-512 e historial de contraseñas"
echo "    Justificación: sin 'remember', un usuario puede cambiar"
echo "    su contraseña actual por la misma anterior. Con remember=5,"
echo "    el sistema rechaza las últimas 5 contraseñas. SHA-512 con"
echo "    10.000 rondas hace que crackear el hash sea muy costoso."
echo ""

COMMON_PASSWORD="/etc/pam.d/common-password"
if [[ ! -f "${COMMON_PASSWORD}.pre-hardening" ]]; then
    run "cp $COMMON_PASSWORD ${COMMON_PASSWORD}.pre-hardening"
fi

if grep -q "pam_unix.so" "$COMMON_PASSWORD" 2>/dev/null; then
    if grep -q "remember=" "$COMMON_PASSWORD"; then
        echo "    [OK] Historial de contraseñas ya configurado"
        OK=$((OK+1))
    else
        run "sed -i 's|pam_unix.so|pam_unix.so sha512 remember=5 rounds=10000|' $COMMON_PASSWORD"
        echo "    [OK] SHA-512, remember=5, rounds=10000 aplicados"
        OK=$((OK+1))
    fi
fi

echo ""
echo "─── Resumen 07_pam.sh ─────────────────────────────────────"
echo "    OK: $OK   WARN: $WARN   ERR: $ERR"
echo ""

export SCRIPT_OK=$OK SCRIPT_WARN=$WARN SCRIPT_ERR=$ERR
