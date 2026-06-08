#!/bin/bash
# =============================================================================
# hardening_main.sh
# -----------------------------------------------------------------------------
# Orquestador principal del framework de hardening basado en CIS Benchmark
# para Debian/Ubuntu. Invoca cada uno de los scripts en orden y muestra
# un resumen final con la cantidad de cambios aplicados.
#
# LOGGING:
#   Toda la salida (consola + scripts hijos) se guarda automáticamente
#   en /var/log/hardening/hardening_YYYY-MM-DD_HHMMSS.log con timestamp
#   por línea, para trazabilidad completa y soporte de auditorías.
#
# Uso:
#   sudo ./hardening_main.sh              # Ejecuta todo
#   sudo ./hardening_main.sh --dry-run    # Simula sin aplicar cambios
#   sudo ./hardening_main.sh --only 05    # Ejecuta solo el script 05_ssh.sh
#   sudo ./hardening_main.sh --skip 08    # Omite el script 08_firewall.sh
# =============================================================================

# Verificar que se ejecute como root — el hardening requiere privilegios totales
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Este script debe ejecutarse como root (usar sudo)"
    exit 1
fi

# Colores para la salida de consola
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

# Directorio donde está este script (permite ejecutarlo desde cualquier ruta)
HARDENING_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export HARDENING_ROOT

# -----------------------------------------------------------------------------
# Configuración de logging persistente con timestamp
# -----------------------------------------------------------------------------
LOG_DIR="/var/log/hardening"
TIMESTAMP=$(date '+%Y-%m-%d_%H%M%S')
LOG_FILE="${LOG_DIR}/hardening_${TIMESTAMP}.log"

# Crear directorio de logs si no existe
mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR"

# Función que antepone timestamp a cada línea que se escribe en el log
log_with_timestamp() {
    while IFS= read -r line; do
        # Quitar códigos de color ANSI para el archivo (legibilidad)
        clean=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $clean" >> "$LOG_FILE"
        echo "$line"   # Reenviar a stdout con colores para la consola
    done
}

# Redirigir TODA la salida de este script (y sus hijos) por la función de log.
# Así no necesitamos modificar los scripts hijos: heredan la redirección.
exec > >(log_with_timestamp) 2>&1

# Export para que los scripts hijos también vean la ruta del log
export LOG_FILE

# -----------------------------------------------------------------------------
# Procesamiento de argumentos
# -----------------------------------------------------------------------------
DRY_RUN=0
ONLY=""
SKIP=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=1; shift ;;
        --only)    ONLY="$2"; shift 2 ;;
        --skip)    SKIP="$2"; shift 2 ;;
        --help|-h)
            echo "Uso: sudo $0 [--dry-run] [--only NN,NN] [--skip NN,NN]"
            echo ""
            echo "  --dry-run     Muestra los cambios sin aplicarlos"
            echo "  --only 01,05  Ejecuta solo los scripts indicados"
            echo "  --skip 09     Omite los scripts indicados"
            echo ""
            echo "  Logs guardados en: $LOG_DIR/hardening_TIMESTAMP.log"
            exit 0 ;;
        *) echo "Opción desconocida: $1 (usar --help)"; exit 1 ;;
    esac
done
export DRY_RUN

# -----------------------------------------------------------------------------
# Banner inicial — incluye metadatos de la ejecución
# -----------------------------------------------------------------------------
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   FRAMEWORK DE HARDENING — CIS Benchmark Debian      ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Este orquestador aplica controles de seguridad agrupados${NC}"
echo -e "${BLUE}según las secciones del CIS Benchmark. Cada script puede${NC}"
echo -e "${BLUE}ejecutarse de forma independiente o desde este main.${NC}"
echo ""
echo -e "${BLUE}Fecha de ejecución : $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BLUE}Hostname           : $(hostname)${NC}"
echo -e "${BLUE}Sistema            : $(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"')${NC}"
echo -e "${BLUE}Log de ejecución   : $LOG_FILE${NC}"
echo ""
[[ $DRY_RUN -eq 1 ]] && echo -e "${YELLOW}>>> MODO DRY-RUN: ningún cambio será aplicado <<<${NC}" && echo ""

# -----------------------------------------------------------------------------
# Lista de scripts a ejecutar (orden importante)
# -----------------------------------------------------------------------------
SCRIPTS=(
    "01_filesystem.sh:Particiones y módulos del kernel (CIS 1.x)"
    "02_services.sh:Deshabilitar servicios innecesarios (CIS 2.x)"
    "03_network.sh:Parámetros de red y kernel sysctl (CIS 3.x)"
    "04_logging.sh:auditd + rsyslog (CIS 4.x)"
    "05_ssh.sh:SSH endurecido (CIS 5.2)"
    "06_users.sh:Usuarios y privilegios (CIS 5.4)"
    "07_pam.sh:PAM y política de contraseñas (CIS 5.3)"
    "08_firewall.sh:Firewall nftables - deny by default"
    "09_fail2ban.sh:Protección contra fuerza bruta (fail2ban)"
    "10_updates.sh:Actualizaciones automáticas de seguridad (CIS 1.9)"
    "11_lynis.sh:Auditoría con Lynis (validación de postura)"
)

# -----------------------------------------------------------------------------
# Ejecución en orden
# -----------------------------------------------------------------------------
TOTAL_OK=0; TOTAL_WARN=0; TOTAL_ERR=0

for entry in "${SCRIPTS[@]}"; do
    script="${entry%%:*}"
    desc="${entry##*:}"
    num="${script:0:2}"

    # Filtro --only: si está definido, solo ejecutar lo indicado
    if [[ -n "$ONLY" ]] && ! echo "$ONLY" | grep -qw "$num"; then
        continue
    fi

    # Filtro --skip: omitir scripts indicados
    if [[ -n "$SKIP" ]] && echo "$SKIP" | grep -qw "$num"; then
        echo -e "${YELLOW}[SKIP]${NC} $script — $desc"
        continue
    fi

    script_path="$HARDENING_ROOT/scripts/$script"
    if [[ ! -f "$script_path" ]]; then
        echo -e "${RED}[ERROR]${NC} No se encontró $script_path"
        continue
    fi

    # Ejecutar el script — cada uno imprime su propio encabezado y resumen
    bash "$script_path"

    # El script exporta sus contadores; los sumamos al total
    TOTAL_OK=$((TOTAL_OK + ${SCRIPT_OK:-0}))
    TOTAL_WARN=$((TOTAL_WARN + ${SCRIPT_WARN:-0}))
    TOTAL_ERR=$((TOTAL_ERR + ${SCRIPT_ERR:-0}))
done

# -----------------------------------------------------------------------------
# Resumen global final
# -----------------------------------------------------------------------------
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║                  RESUMEN GLOBAL                      ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo -e "  ${GREEN}Controles aplicados correctamente : $TOTAL_OK${NC}"
echo -e "  ${YELLOW}Advertencias                      : $TOTAL_WARN${NC}"
echo -e "  ${RED}Errores                           : $TOTAL_ERR${NC}"
echo ""
echo -e "  ${BLUE}Log completo guardado en: $LOG_FILE${NC}"
echo ""

# Aviso de reinicio si es necesario
if [[ -f /var/run/reboot-required ]]; then
    echo -e "${YELLOW}>>> AVISO: El sistema requiere reinicio para aplicar todos los cambios${NC}"
    echo -e "${YELLOW}>>> Reiniciar con: sudo reboot${NC}"
fi
echo ""

# Esperar a que el pipe de logging vacíe su buffer antes de salir
# (sin esto, las últimas líneas pueden no llegar al archivo)
sleep 1
