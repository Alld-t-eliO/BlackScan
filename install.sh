set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# =============================================================================
# Variables globales
# =============================================================================
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
VENV_DIR="$ROOT_DIR/venv"
PYTHON_BIN="${PYTHON:-python3}"
INSTALL_DEV=false
INSTALL_ALL=false
USE_VENV=true
OS_TYPE="unknown"

# =============================================================================
# Fonctions d'affichage
# =============================================================================
print_header() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}                   BLACKSCAN - INSTALLATION                   ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_step() {
    echo -e "\n${PURPLE}▶ $1${NC}"
}

print_separator() {
    echo -e "${CYAN}────────────────────────────────────────────────────────────────────${NC}"
}

# =============================================================================
# Détection de l'OS
# =============================================================================
detect_os() {
    print_step "Détection du système d'exploitation..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS_TYPE="linux"
        print_success "OS détecté : Linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS_TYPE="macos"
        print_success "OS détecté : macOS"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        OS_TYPE="windows"
        print_warning "OS détecté : Windows (fonctionnalité expérimentale)"
    else
        OS_TYPE="unknown"
        print_warning "OS non reconnu : $OSTYPE"
    fi
}

# =============================================================================
# Vérification des prérequis
# =============================================================================
check_prerequisites() {
    print_step "Vérification des prérequis..."
    
    # Vérification de Python
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        print_error "Python 3.10 ou supérieur est requis mais n'est pas installé."
        echo -e "  ${YELLOW}Installez Python depuis : https://www.python.org/downloads/${NC}"
        exit 1
    fi
    
    # Vérification de la version Python
    PYTHON_VERSION=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
    
    if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 10 ]]; then
        print_error "Python $PYTHON_VERSION détecté. BlackScan nécessite Python 3.10 ou supérieur."
        exit 1
    fi
    
    print_success "Python $PYTHON_VERSION détecté"
    
    # Vérification de pip
    if ! command -v pip3 >/dev/null 2>&1 && ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
        print_warning "pip n'est pas disponible. Tentative d'installation..."
        "$PYTHON_BIN" -m ensurepip --upgrade || {
            print_error "Impossible d'installer pip automatiquement."
            echo -e "  ${YELLOW}Installez pip manuellement puis réessayez.${NC}"
            exit 1
        }
    fi
    
    print_success "pip disponible"
    
    # Vérification de git (optionnel)
    if command -v git >/dev/null 2>&1; then
        print_success "git détecté"
    else
        print_warning "git n'est pas installé (optionnel, nécessaire pour le développement)"
    fi
    
    # Vérification des dépendances système (Linux)
    if [[ "$OS_TYPE" == "linux" ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            print_info "Distribution Debian/Ubuntu détectée"
            print_info "Les dépendances système seront installées automatiquement"
        elif command -v yum >/dev/null 2>&1; then
            print_info "Distribution RHEL/CentOS détectée"
            print_info "Les dépendances système seront installées automatiquement"
        elif command -v dnf >/dev/null 2>&1; then
            print_info "Distribution Fedora détectée"
            print_info "Les dépendances système seront installées automatiquement"
        fi
    fi
}

# =============================================================================
# Installation des dépendances système
# =============================================================================
install_system_dependencies() {
    print_step "Installation des dépendances système..."
    
    if [[ "$OS_TYPE" != "linux" ]]; then
        print_info "Système non-Linux, installation des dépendances système ignorée"
        return 0
    fi
    
    # Vérification des droits sudo
    if ! command -v sudo >/dev/null 2>&1; then
        print_warning "sudo n'est pas disponible, installation des dépendances système ignorée"
        return 0
    fi
    
    local deps=""
    
    # Dépendances communes
    deps="build-essential libssl-dev libffi-dev"
    
    # Dépendances spécifiques
    if [[ "$INSTALL_ALL" == true ]] || [[ "$INSTALL_DEV" == true ]]; then
        deps="$deps git curl wget"
    fi
    
    # Détection du gestionnaire de paquets
    if command -v apt-get >/dev/null 2>&1; then
        print_info "Installation des paquets : $deps"
        sudo apt-get update -qq || true
        sudo apt-get install -y -qq $deps || {
            print_warning "Échec de l'installation de certaines dépendances système"
            print_info "Continuez l'installation, les dépendances Python seront installées"
        }
    elif command -v dnf >/dev/null 2>&1; then
        print_info "Installation des paquets : $deps"
        sudo dnf install -y $deps || {
            print_warning "Échec de l'installation de certaines dépendances système"
            print_info "Continuez l'installation, les dépendances Python seront installées"
        }
    elif command -v yum >/dev/null 2>&1; then
        print_info "Installation des paquets : $deps"
        sudo yum install -y $deps || {
            print_warning "Échec de l'installation de certaines dépendances système"
            print_info "Continuez l'installation, les dépendances Python seront installées"
        }
    else
        print_warning "Aucun gestionnaire de paquets reconnu"
        print_info "Assurez-vous que les dépendances suivantes sont installées : $deps"
    fi
    
    print_success "Dépendances système installées"
}

# =============================================================================
# Installation des dépendances Python
# =============================================================================
install_python_dependencies() {
    print_step "Installation des dépendances Python..."
    
    if [[ "$USE_VENV" == true ]]; then
        print_info "Création de l'environnement virtuel..."
        "$PYTHON_BIN" -m venv "$VENV_DIR"
        PIP_CMD="$VENV_DIR/bin/pip"
        PYTHON_CMD="$VENV_DIR/bin/python"
    else
        PIP_CMD="pip3"
        PYTHON_CMD="$PYTHON_BIN"
    fi
    
    print_info "Mise à jour de pip, setuptools et wheel..."
    "$PIP_CMD" install --upgrade pip setuptools wheel -q
    
    # Installation des dépendances de base
    print_info "Installation des dépendances de base..."
    "$PIP_CMD" install -e . -q
    
    # Installation des extras optionnels
    if [[ "$INSTALL_ALL" == true ]]; then
        print_info "Installation de toutes les dépendances optionnelles..."
        "$PIP_CMD" install -e ".[audit,dev,all]" -q
    elif [[ "$INSTALL_DEV" == true ]]; then
        print_info "Installation des dépendances de développement..."
        "$PIP_CMD" install -e ".[dev]" -q
    fi
    
    print_success "Dépendances Python installées"
}

# =============================================================================
# Installation des outils externes recommandés
# =============================================================================
install_external_tools() {
    print_step "Installation des outils externes recommandés..."
    
    local tools_installed=0
    local tools_missing=0
    
    # Vérification des outils existants
    for tool in nmap nuclei httpx subfinder dnsx; do
        if command -v "$tool" >/dev/null 2>&1; then
            print_success "$tool déjà installé"
            ((tools_installed++))
        else
            print_warning "$tool non trouvé"
            ((tools_missing++))
        fi
    done
    
    if [[ $tools_missing -gt 0 ]]; then
        print_info "$tools_missing outils manquants sur $((tools_installed + tools_missing))"
        print_info "Vous pouvez les installer manuellement :"
        echo -e "  ${YELLOW}• go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${NC}"
        echo -e "  ${YELLOW}• go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest${NC}"
        echo -e "  ${YELLOW}• go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest${NC}"
        echo -e "  ${YELLOW}• go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest${NC}"
    else
        print_success "Tous les outils externes recommandés sont installés !"
    fi
}

# =============================================================================
# Test de l'installation
# =============================================================================
test_installation() {
    print_step "Test de l'installation..."
    
    if [[ "$USE_VENV" == true ]]; then
        PYTHON_CMD="$VENV_DIR/bin/python"
    else
        PYTHON_CMD="$PYTHON_BIN"
    fi
    
    # Test : import du package
    if "$PYTHON_CMD" -c "import network_scanner" 2>/dev/null; then
        print_success "Import du package réussi"
    else
        print_error "Échec de l'import du package"
        return 1
    fi
    
    # Test : affichage de l'aide
    if "$PYTHON_CMD" -m network_scanner --help >/dev/null 2>&1; then
        print_success "Commande --help fonctionne"
    else
        print_error "Échec de l'exécution de --help"
        return 1
    fi
    
    # Test : liste des exploits
    if "$PYTHON_CMD" -c "from network_scanner.payloads.exploits import list_exploits; print(list_exploits())" >/dev/null 2>&1; then
        print_success "Import des exploits réussi"
    else
        print_warning "Import des exploits échoué (dépendances optionnelles manquantes ?)"
    fi
    
    return 0
}

# =============================================================================
# Création des dossiers nécessaires
# =============================================================================
create_directories() {
    print_step "Création des dossiers nécessaires..."
    
    mkdir -p "$ROOT_DIR/reports"
    mkdir -p "$ROOT_DIR/logs"
    mkdir -p "$ROOT_DIR/network_scanner/payloads/wordlists"
    
    print_success "Dossiers créés"
}

# =============================================================================
# Affichage du résumé final
# =============================================================================
show_summary() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${GREEN}                   INSTALLATION RÉUSSIE !                      ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${WHITE}📁 Dossier d'installation :${NC} $ROOT_DIR"
    
    if [[ "$USE_VENV" == true ]]; then
        echo -e "${WHITE}🐍 Environnement virtuel :${NC} $VENV_DIR"
        echo -e "\n${YELLOW}Pour activer l'environnement virtuel :${NC}"
        echo -e "  ${CYAN}source $VENV_DIR/bin/activate${NC}"
        echo -e "\n${YELLOW}Pour exécuter BlackScan :${NC}"
        echo -e "  ${CYAN}python scanner.py --help${NC}"
        echo -e "  ${CYAN}python scanner.py -t 192.168.1.1 --authorized --profile quick${NC}"
    else
        echo -e "\n${YELLOW}Pour exécuter BlackScan :${NC}"
        echo -e "  ${CYAN}python3 scanner.py --help${NC}"
        echo -e "  ${CYAN}python3 scanner.py -t 192.168.1.1 --authorized --profile quick${NC}"
    fi
    
    echo -e "\n${YELLOW}Pour l'interface TUI :${NC}"
    echo -e "  ${CYAN}python scanner.py --tui${NC}"
    
    echo -e "\n${YELLOW}Pour les exploits (lab uniquement) :${NC}"
    echo -e "  ${CYAN}python scanner.py -t 192.168.1.1 --authorized --intrusive-checks --exploit${NC}"
    
    echo -e "\n${WHITE}📚 Documentation :${NC}"
    echo -e "  • README.md   - Guide d'utilisation"
    echo -e "  • dev.md      - Notes de développement"
    
    echo -e "\n${GREEN}⚠️  N'oubliez pas :${NC}"
    echo -e "  • Utilisez --authorized pour confirmer que vous avez l'autorisation"
    echo -e "  • Les exploits nécessitent --intrusive-checks"
    echo -e "  • Testez UNIQUEMENT sur vos propres machines en laboratoire"
    
    echo -e "\n${CYAN}────────────────────────────────────────────────────────────────────${NC}\n"
}

# =============================================================================
# Aide
# =============================================================================
show_help() {
    cat << EOF
BlackScan - Installation Script

Usage:
    ./install.sh [OPTIONS]

Options:
    --dev           Install development dependencies (ruff, pytest, mypy, etc.)
    --all           Install all optional dependencies (mysql, ssh, http, etc.)
    --no-venv       Install directly in the current environment (not recommended)
    --help          Show this help message

Examples:
    ./install.sh                # Installation de base
    ./install.sh --dev          # Installation avec outils de développement
    ./install.sh --all          # Installation complète avec toutes les dépendances
    ./install.sh --no-venv      # Installation dans l'environnement actuel

Dependencies:
    Python 3.10+                # Obligatoire
    pip                         # Obligatoire
    git                         # Optionnel (pour le développement)
    nmap, nuclei, httpx, etc.   # Optionnels (pour l'enrichissement externe)

After installation:
    source venv/bin/activate    # Activer l'environnement virtuel
    python scanner.py --help    # Voir les options disponibles
    python scanner.py --tui     # Interface TUI

EOF
}

# =============================================================================
# Désinstallation
# =============================================================================
uninstall() {
    print_step "Désinstallation de BlackScan..."
    
    if [[ -d "$VENV_DIR" ]]; then
        print_info "Suppression de l'environnement virtuel..."
        rm -rf "$VENV_DIR"
        print_success "Environnement virtuel supprimé"
    fi
    
    if [[ -d "$ROOT_DIR/__pycache__" ]]; then
        print_info "Suppression des fichiers __pycache__..."
        find "$ROOT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        print_success "Fichiers temporaires supprimés"
    fi
    
    print_success "Désinstallation terminée"
    echo -e "\n${YELLOW}Les dossiers suivants n'ont pas été supprimés (contenu utilisateur) :${NC}"
    echo -e "  • $ROOT_DIR/reports/"
    echo -e "  • $ROOT_DIR/logs/"
    echo -e "  • $ROOT_DIR/venv/ (si elle existe encore)"
}

# =============================================================================
# Fonction principale
# =============================================================================
main() {
    # Traitement des arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dev)
                INSTALL_DEV=true
                shift
                ;;
            --all)
                INSTALL_ALL=true
                shift
                ;;
            --no-venv)
                USE_VENV=false
                shift
                ;;
            --uninstall)
                uninstall
                exit 0
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}Option inconnue : $1${NC}"
                echo "Utilisez --help pour voir les options disponibles."
                exit 1
                ;;
        esac
    done
    
    # Affichage du header
    print_header
    
    # Vérification des prérequis
    check_prerequisites
    
    # Détection de l'OS
    detect_os
    
    # Installation des dépendances système
    if [[ "$OS_TYPE" == "linux" ]]; then
        install_system_dependencies
    else
        print_info "Système non-Linux, installation des dépendances système ignorée"
    fi
    
    # Création des dossiers
    create_directories
    
    # Installation des dépendances Python
    install_python_dependencies
    
    # Vérification des outils externes
    install_external_tools
    
    # Test de l'installation
    if test_installation; then
        print_success "Installation validée"
    else
        print_warning "Certains tests ont échoué, mais l'installation est probablement fonctionnelle"
    fi
    
    # Affichage du résumé
    show_summary
}

# =============================================================================
# Exécution
# =============================================================================
main "$@"