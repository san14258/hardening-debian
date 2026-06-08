#!/bin/bash
# =============================================================================
# 11_lynis.sh — Auditoría con Lynis (validación de postura de seguridad)
# -----------------------------------------------------------------------------
# QUÉ HACE ESTE SCRIPT:
#   1. Instala Lynis si no está presente. Lynis es una herramienta de
#      auditoría de seguridad de código abierto (de CISOfy) ampliamente
#      usada para validar el endurecimiento de sistemas Linux/Unix.
#   2. Ejecuta una auditoría completa del sistema en modo --quick (no
#      interactivo) y guarda el reporte en /var/log/lynis-report.dat.
#   3. Extrae y muestra el "Hardening Index" — un valor de 0 a 100 que
#      representa el nivel de endurecimiento del sistema.
#   4. Lista las recomendaciones (warnings y suggestions) que Lynis
#      detectó, para que se puedan revisar manualmente.
#   5. Copia el reporte completo a /var/log/hardening/ junto con los
#      logs del framework, para tener todo el historial en un solo lugar.
#
#   USO COMPLEMENTARIO: Lynis es el espejo de los demás scripts. Después
#   de aplicar el hardening, Lynis verifica que efectivamente se aplicó
#   correctamente y detecta huecos que se pudieron haber pasado por alto.
# =============================================================================

[[ $EUID -ne 0 ]] && { echo "Ejecutar como root"; exit 1; }
DRY_RUN=${DRY_RUN:-0}
OK=0; WARN=0; ERR=0

run() {
    [[ $DRY_RUN -eq 1 ]] && echo "  [DRY-RUN] $*" || eval "$@"
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " 11_lynis.sh — Auditoría con Lynis"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo " Objetivo: validar que el hardening aplicado por los scripts"
echo " anteriores realmente surtió efecto. Lynis recorre el sistema"
echo " y genera un score de 0 a 100 (Hardening Index) más una lista"
echo " de recomendaciones. Es la evidencia objetiva del nivel de"
echo " endurecimiento alcanzado."
echo ""

# -----------------------------------------------------------------------------
# 11.1 — Instalación de Lynis
# -----------------------------------------------------------------------------
echo ">>> [1/4] Instalando Lynis"
echo "    Justificación: Lynis es la herramienta estándar de la industria"
echo "    para auditar postura de seguridad en Linux. Es usada por equipos"
echo "    de pentesting y compliance (PCI-DSS, HIPAA, ISO 27001)."
echo ""

if dpkg -l lynis 2>/dev/null | grep -q "^ii"; then
    echo "    [OK] Lynis ya estaba instalado"
    OK=$((OK+1))
else
    run "apt-get install -y lynis"
    echo "    [OK] Lynis instalado"
    OK=$((OK+1))
fi

# Mostrar versión instalada
if [[ $DRY_RUN -eq 0 ]] && command -v lynis &>/dev/null; then
    VERSION=$(lynis show version 2>/dev/null | head -1)
    echo "    [INFO] Versión instalada: $VERSION"
fi

# -----------------------------------------------------------------------------
# 11.2 — Ejecutar auditoría
# -----------------------------------------------------------------------------
echo ""
echo ">>> [2/4] Ejecutando auditoría completa del sistema"
echo "    Justificación: 'lynis audit system' recorre más de 200 controles"
echo "    (boot, kernel, autenticación, red, malware, etc.) y los compara"
echo "    contra benchmarks como CIS. La opción --quick lo hace no interactivo."
echo ""

LYNIS_LOG="/var/log/lynis.log"
LYNIS_REPORT="/var/log/lynis-report.dat"

if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [DRY-RUN] lynis audit system --quick --quiet"
else
    echo "    Ejecutando auditoría (puede tardar 1-2 minutos)..."
    # --quick: no espera enter al final de cada sección
    # --quiet: menos verboso en stdout (igualmente todo va a /var/log/lynis.log)
    lynis audit system --quick --quiet >/dev/null 2>&1
    echo "    [OK] Auditoría completada"
    OK=$((OK+1))
    echo "    [INFO] Log detallado en: $LYNIS_LOG"
    echo "    [INFO] Reporte parseable en: $LYNIS_REPORT"
fi

# -----------------------------------------------------------------------------
# 11.3 — Extraer y mostrar el Hardening Index
# -----------------------------------------------------------------------------
echo ""
echo ">>> [3/4] Extrayendo Hardening Index y conteo de warnings/suggestions"
echo "    Justificación: el Hardening Index es el dato numérico que"
echo "    podemos presentar como evidencia del nivel de seguridad."
echo "    Valor de referencia: <60 deficiente, 60-79 aceptable, ≥80 bueno."
echo ""

if [[ $DRY_RUN -eq 0 && -f "$LYNIS_REPORT" ]]; then
    # Lynis guarda el score en la línea: hardening_index=NN
    SCORE=$(grep "^hardening_index=" "$LYNIS_REPORT" | cut -d= -f2)
    WARNINGS_COUNT=$(grep -c "^warning\[\]=" "$LYNIS_REPORT" 2>/dev/null || echo 0)
    SUGG_COUNT=$(grep -c "^suggestion\[\]=" "$LYNIS_REPORT" 2>/dev/null || echo 0)

    if [[ -n "$SCORE" ]]; then
        echo ""
        echo "    ┌─────────────────────────────────────────────┐"
        echo "    │  HARDENING INDEX: $SCORE / 100"
        echo "    │  Warnings   : $WARNINGS_COUNT"
        echo "    │  Sugerencias: $SUGG_COUNT"
        echo "    └─────────────────────────────────────────────┘"
        echo ""

        if [[ "$SCORE" -ge 80 ]]; then
            echo "    [OK] Nivel de hardening BUENO ($SCORE/100)"
            OK=$((OK+1))
        elif [[ "$SCORE" -ge 60 ]]; then
            echo "    [WARN] Nivel de hardening ACEPTABLE ($SCORE/100)"
            WARN=$((WARN+1))
        else
            echo "    [ERROR] Nivel de hardening INSUFICIENTE ($SCORE/100)"
            ERR=$((ERR+1))
        fi
    else
        echo "    [WARN] No se pudo extraer el Hardening Index del reporte"
        WARN=$((WARN+1))
    fi
fi

# -----------------------------------------------------------------------------
# 11.4 — Mostrar warnings y guardar reporte
# -----------------------------------------------------------------------------
echo ""
echo ">>> [4/4] Resumen de warnings y archivado del reporte"
echo "    Justificación: los warnings son problemas que Lynis considera"
echo "    importantes — vale la pena revisarlos uno por uno. Las"
echo "    sugerencias son mejoras opcionales."
echo ""

if [[ $DRY_RUN -eq 0 && -f "$LYNIS_REPORT" ]]; then
    WARNINGS=$(grep "^warning\[\]=" "$LYNIS_REPORT" 2>/dev/null)
    if [[ -n "$WARNINGS" ]]; then
        echo "    Warnings detectados por Lynis:"
        echo "$WARNINGS" | head -10 | while read -r line; do
            # Limpiar el formato: warning[]=ID|Mensaje|...
            msg=$(echo "$line" | cut -d= -f2- | cut -d'|' -f2)
            echo "      → $msg"
        done

        TOTAL_W=$(echo "$WARNINGS" | wc -l)
        if [[ "$TOTAL_W" -gt 10 ]]; then
            echo "      ... y $((TOTAL_W - 10)) más (ver $LYNIS_LOG)"
        fi
    else
        echo "    [OK] Sin warnings críticos detectados"
        OK=$((OK+1))
    fi

    # Copiar reporte de Lynis al directorio de logs del framework
    LOG_DIR="/var/log/hardening"
    if [[ -d "$LOG_DIR" ]]; then
        TIMESTAMP=$(date '+%Y-%m-%d_%H%M%S')
        cp "$LYNIS_REPORT" "$LOG_DIR/lynis-report_${TIMESTAMP}.dat"
        cp "$LYNIS_LOG"    "$LOG_DIR/lynis_${TIMESTAMP}.log" 2>/dev/null
        echo ""
        echo "    [OK] Reporte de Lynis archivado en $LOG_DIR/"
        OK=$((OK+1))
    fi

    echo ""
    echo "    Para ver el reporte completo: less $LYNIS_LOG"
    echo "    Para ver detalles de un control específico: lynis show details TEST-ID"
fi

echo ""
echo "─── Resumen 11_lynis.sh ───────────────────────────────────"
echo "    OK: $OK   WARN: $WARN   ERR: $ERR"
echo ""

export SCRIPT_OK=$OK SCRIPT_WARN=$WARN SCRIPT_ERR=$ERR
