#!/bin/bash
# =============================================================================
# 07_pam.sh — CIS Sección 5.3  (VERSIÓN CORREGIDA)
# -----------------------------------------------------------------------------
# QUÉ HACE ESTE SCRIPT:
#   1. Instala libpam-pwquality y configura una política estricta de
#      contraseñas: 14+ caracteres, con mayúsculas, minúsculas, dígitos
#      y especiales; sin repeticiones; sin estar en diccionario.
#   2. Configura pam_faillock: tras 5 intentos fallidos, la cuenta se
#      bloquea por 15 minutos. Protección contra fuerza bruta local.
#   3. Configura hashing fuerte (yescrypt, default de Debian 12) e
#      historial de 5 contraseñas (no reutilizar las últimas 5).
#
#   CAMBIOS RESPECTO A LA VERSIÓN ANTERIOR:
#   - FIX CRÍTICO: las 3 líneas de pam_faillock (preauth/authfail/authsucc)
#     se insertan en el ORDEN correcto relativo a pam_unix. La versión
#     previa agregaba 'authfail' al final del archivo, lo que hacía que
#     TODO login válido (root incluido) terminara ejecutando authfail con
#     [default=die] y rebotara con "Login incorrect". Ya no.
#   - Los parámetros (deny/unlock_time) van en /etc/security/faillock.conf,
#     no inline en cada línea PAM (estilo recomendado por CIS).
#   - Idempotente: siempre reconstruye common-auth desde el backup limpio.
#   - Validación estructural + ROLLBACK automático si la estructura queda mal.
#
#   ATENCIÓN: PAM es delicado. Si rompemos common-auth nadie puede
#   loguearse. Por eso, ANTES de cerrar la sesión donde corrés esto,
#   verificá el login en OTRA TTY (Alt+F2). Ver SAFETY_NET al final.
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
echo " se rompe un archivo. Hacemos backup y validamos antes de"
echo " dar por bueno el cambio. Probá el login en otra TTY."
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
echo "    NOTA: enforce_for_root=1 aplica la política también a root."
echo "    Es lo que pide CIS, pero implica que para RECUPERAR la pass de"
echo "    root (init=/bin/bash) también vas a necesitar 14+ chars y las"
echo "    4 clases. Tenelo presente."
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
    run "cp -a $PWQ_CONF ${PWQ_CONF}.pre-hardening"
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
# 7.2 — pam_faillock (bloqueo por intentos fallidos)  [REESCRITO]
# -----------------------------------------------------------------------------
echo ""
echo ">>> [2/3] Configurando pam_faillock contra fuerza bruta"
echo "    Justificación: sin esto, un atacante puede probar contraseñas"
echo "    infinitamente. Con faillock, tras 5 intentos fallidos la"
echo "    cuenta se bloquea 15 minutos."
echo ""
echo "    Orden correcto de las 3 líneas (clave para no romper el login):"
echo "      preauth  -> ANTES de pam_unix (chequea si ya está bloqueada)"
echo "      authfail -> JUSTO DESPUÉS de pam_unix (cuenta el fallo)"
echo "      authsucc -> después de authfail (resetea el contador si entró)"
echo ""

COMMON_AUTH="/etc/pam.d/common-auth"

# --- (a) Backup LIMPIO: solo la primera vez, antes de tocar nada ---
if [[ ! -f "${COMMON_AUTH}.pre-hardening" ]]; then
    run "cp -a $COMMON_AUTH ${COMMON_AUTH}.pre-hardening"
    echo "    [OK] Backup: ${COMMON_AUTH}.pre-hardening"
    OK=$((OK+1))
fi

# --- (b) Parámetros en faillock.conf (no inline) — estilo CIS ---
FAILLOCK_CONF="/etc/security/faillock.conf"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [DRY-RUN] Setear deny/unlock_time/fail_interval en $FAILLOCK_CONF"
else
    [[ -f "$FAILLOCK_CONF" && ! -f "${FAILLOCK_CONF}.pre-hardening" ]] && \
        cp -a "$FAILLOCK_CONF" "${FAILLOCK_CONF}.pre-hardening"
    touch "$FAILLOCK_CONF"
    set_faillock() {   # $1=clave  $2=valor
        local k="$1" v="$2"
        if grep -qE "^[#[:space:]]*${k}([[:space:]]|=)" "$FAILLOCK_CONF"; then
            sed -i -E "s|^[#[:space:]]*${k}.*|${k} = ${v}|" "$FAILLOCK_CONF"
        else
            echo "${k} = ${v}" >> "$FAILLOCK_CONF"
        fi
    }
    set_faillock deny 5
    set_faillock unlock_time 900
    set_faillock fail_interval 900
    # even_deny_root NO se activa: queremos que root SIEMPRE pueda entrar
    # como vía de emergencia para desbloquear a otros usuarios.
fi
echo "    [OK] $FAILLOCK_CONF: deny=5, unlock_time=900, fail_interval=900"
OK=$((OK+1))

# --- (c) Insertar las 3 líneas en common-auth, SIEMPRE desde el limpio ---
# Reconstruir desde el backup limpio garantiza idempotencia: corras las
# veces que corras, el resultado es exactamente el mismo.
if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [DRY-RUN] Reconstruir $COMMON_AUTH con faillock en orden correcto"
else
    awk '
        # Insertar preauth antes de la 1ra línea de pam_unix, y
        # authfail+authsucc justo después de ella. Solo en la 1ra ocurrencia.
        !done && /pam_unix\.so/ {
            print "auth\trequired\t\t\tpam_faillock.so preauth"
            print
            print "auth\t[default=die]\t\t\tpam_faillock.so authfail"
            print "auth\tsufficient\t\t\tpam_faillock.so authsucc"
            done = 1
            next
        }
        { print }
    ' "${COMMON_AUTH}.pre-hardening" > "${COMMON_AUTH}.new" && \
    mv "${COMMON_AUTH}.new" "$COMMON_AUTH"
fi

# --- (d) VALIDACIÓN ESTRUCTURAL + ROLLBACK automático ---
# No podemos probar la auth real sin la contraseña, pero sí verificar que
# el orden quedó bien. Si no, restauramos el backup para no dejar el
# sistema sin login.
if [[ $DRY_RUN -eq 0 ]]; then
    ln_unix=$(grep -n 'pam_unix\.so'             "$COMMON_AUTH" | head -1 | cut -d: -f1)
    ln_pre=$( grep -n 'pam_faillock.*preauth'    "$COMMON_AUTH" | head -1 | cut -d: -f1)
    ln_fail=$(grep -n 'pam_faillock.*authfail'   "$COMMON_AUTH" | head -1 | cut -d: -f1)
    ln_succ=$(grep -n 'pam_faillock.*authsucc'   "$COMMON_AUTH" | head -1 | cut -d: -f1)

    if [[ -n "$ln_unix" && -n "$ln_pre" && -n "$ln_fail" && -n "$ln_succ" \
          && "$ln_pre"  -lt "$ln_unix" \
          && "$ln_fail" -gt "$ln_unix" \
          && "$ln_succ" -gt "$ln_fail" ]]; then
        echo "    [OK] pam_faillock en orden correcto (preauth<unix<authfail<authsucc)"
        OK=$((OK+1))
    else
        echo "    [ERROR] Estructura PAM inválida → restaurando ${COMMON_AUTH}.pre-hardening"
        cp -a "${COMMON_AUTH}.pre-hardening" "$COMMON_AUTH"
        ERR=$((ERR+1))
    fi
fi

# -----------------------------------------------------------------------------
# 7.3 — Hashing fuerte e historial de contraseñas  [CORREGIDO]
# -----------------------------------------------------------------------------
echo ""
echo ">>> [3/3] Configurando hashing fuerte e historial de contraseñas"
echo "    Justificación: con remember=5 el sistema rechaza las últimas 5"
echo "    contraseñas. El algoritmo es yescrypt (default de Debian 12),"
echo "    superior a SHA-512 frente a ataques con hardware especializado."
echo ""
echo "    Si tu documentación del proyecto exige SHA-512 explícito,"
echo "    descomentá el bloque marcado [OPCIONAL SHA-512] más abajo."
echo ""

COMMON_PASSWORD="/etc/pam.d/common-password"
if [[ ! -f "${COMMON_PASSWORD}.pre-hardening" ]]; then
    run "cp -a $COMMON_PASSWORD ${COMMON_PASSWORD}.pre-hardening"
fi

if grep -q "pam_unix.so" "$COMMON_PASSWORD" 2>/dev/null; then
    if grep -q "remember=" "$COMMON_PASSWORD"; then
        echo "    [OK] Historial de contraseñas ya configurado"
        OK=$((OK+1))
    else
        # Mantiene yescrypt (no lo pisamos) y solo agrega remember=5.
        run "sed -i '/pam_unix\.so/ s/\$/ remember=5/' $COMMON_PASSWORD"
        echo "    [OK] yescrypt + remember=5 aplicados"
        OK=$((OK+1))

        # --- [OPCIONAL SHA-512] ---------------------------------------------
        # Para forzar SHA-512 en lugar de yescrypt, descomentá estas 2 líneas.
        # No basta con AGREGAR 'sha512': hay que REEMPLAZAR 'yescrypt', porque
        # si quedan los dos, el comportamiento es indefinido.
        # run "sed -i 's/\byescrypt\b/sha512/' $COMMON_PASSWORD"
        # run "sed -i '/pam_unix\.so/ s/\$/ rounds=10000/' $COMMON_PASSWORD"
        # --------------------------------------------------------------------
    fi
else
    echo "    [WARN] No se encontró pam_unix.so en $COMMON_PASSWORD"
    WARN=$((WARN+1))
fi

echo ""
echo "─── Resumen 07_pam.sh ─────────────────────────────────────"
echo "    OK: $OK   WARN: $WARN   ERR: $ERR"
echo ""
echo "    >> Antes de cerrar esta sesión, ABRÍ otra TTY (Alt+F2) y"
echo "       verificá que podés loguearte. Si algo falla, restaurá con:"
echo "         cp -a /etc/pam.d/common-auth.pre-hardening /etc/pam.d/common-auth"
echo ""

export SCRIPT_OK=$OK SCRIPT_WARN=$WARN SCRIPT_ERR=$ERR
