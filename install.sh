```bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
VENV_DIR="$ROOT_DIR/venv"
PYTHON_BIN="${PYTHON:-python3}"
INSTALL_DEV=false
INSTALL_ALL=false
USE_VENV=true
OS_TYPE="unknown"

print_header() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}                   BLACKSCAN - INSTALLATION                   ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
}

print_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

print_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

print_info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

print_step() {
    echo -e "\n${PURPLE}▶ $1${NC}"
}

print_separator() {
    echo -e "${CYAN}────────────────────────────────────────────────────────────────────${NC}"
}

detect_os() {
    print_step "Detecting operating system..."

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS_TYPE="linux"
        print_success "OS detected: Linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS_TYPE="macos"
        print_success "OS detected: macOS"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        OS_TYPE="windows"
        print_warning "OS detected: Windows"
    else
        OS_TYPE="unknown"
        print_warning "OS not recognised: $OSTYPE"
    fi
}

check_prerequisites() {

    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        print_error "Python 3.10 or newer is required but is not installed."
        echo -e "  ${YELLOW}Install Python from: https://www.python.org/downloads/${NC}"
        exit 1
    fi

    PYTHON_VERSION=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

    if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 10 ]]; then
        print_error "Python $PYTHON_VERSION detected. BlackScan requires Python 3.10 or newer."
        exit 1
    fi

    print_success "Python $PYTHON_VERSION detected"

    if ! command -v pip3 >/dev/null 2>&1 && ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
        print_warning "pip is not available. Attempting to install it..."
        "$PYTHON_BIN" -m ensurepip --upgrade || {
            print_error "Unable to install pip automatically."
            echo -e "  ${YELLOW}Install pip manually and try again.${NC}"
            exit 1
        }
    fi

    print_success "pip is available"

    if command -v git >/dev/null 2>&1; then
        print_success "git detected"
    else
        print_warning "git is not installed (optional, required for development)"
    fi

    if [[ "$OS_TYPE" == "linux" ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            print_info "Debian/Ubuntu distribution detected"
            print_info "System dependencies will be installed automatically"
        elif command -v yum >/dev/null 2>&1; then
            print_info "RHEL/CentOS distribution detected"
            print_info "System dependencies will be installed automatically"
        elif command -v dnf >/dev/null 2>&1; then
            print_info "Fedora distribution detected"
            print_info "System dependencies will be installed automatically"
        fi
    fi
}


install_system_dependencies() {
    print_step "Installing system dependencies..."

    if [[ "$OS_TYPE" != "linux" ]]; then
        print_info "Non-Linux system, skipping system dependency installation"
        return 0
    fi

    if ! command -v sudo >/dev/null 2>&1; then
        print_warning "sudo is not available, skipping system dependency installation"
        return 0
    fi

    local deps=""

    deps="build-essential libssl-dev libffi-dev"

    if [[ "$INSTALL_ALL" == true ]] || [[ "$INSTALL_DEV" == true ]]; then
        deps="$deps git curl wget"
    fi

    if command -v apt-get >/dev/null 2>&1; then
        print_info "Installing packages: $deps"
        sudo apt-get update -qq || true
        sudo apt-get install -y -qq $deps || {
            print_warning "Failed to install some system dependencies"
            print_info "Continuing installation; Python dependencies will still be installed"
        }
    elif command -v dnf >/dev/null 2>&1; then
        print_info "Installing packages: $deps"
        sudo dnf install -y $deps || {
            print_warning "Failed to install some system dependencies"
            print_info "Continuing installation; Python dependencies will still be installed"
        }
    elif command -v yum >/dev/null 2>&1; then
        print_info "Installing packages: $deps"
        sudo yum install -y $deps || {
            print_warning "Failed to install some system dependencies"
            print_info "Continuing installation; Python dependencies will still be installed"
        }
    else
        print_warning "No supported package manager detected"
        print_info "Make sure the following dependencies are installed: $deps"
    fi

    print_success "System dependencies installed"
}


install_python_dependencies() {
    print_step "Installing Python dependencies..."

    if [[ "$USE_VENV" == true ]]; then
        print_info "Creating virtual environment..."
        "$PYTHON_BIN" -m venv "$VENV_DIR"
        PIP_CMD="$VENV_DIR/bin/pip"
        PYTHON_CMD="$VENV_DIR/bin/python"
    else
        PIP_CMD="pip3"
        PYTHON_CMD="$PYTHON_BIN"
    fi

    print_info "Upgrading pip, setuptools, and wheel..."
    "$PIP_CMD" install --upgrade pip setuptools wheel -q

    print_info "Installing base dependencies..."
    "$PIP_CMD" install -e . -q

    if [[ "$INSTALL_ALL" == true ]]; then
        print_info "Installing all optional dependencies..."
        "$PIP_CMD" install -e ".[audit,dev,all]" -q
    elif [[ "$INSTALL_DEV" == true ]]; then
        print_info "Installing development dependencies..."
        "$PIP_CMD" install -e ".[dev]" -q
    fi

    print_success "Python dependencies installed"
}

install_external_tools() {
    print_step "Checking recommended external tools..."

    local tools_installed=0
    local tools_missing=0

    for tool in nmap nuclei httpx subfinder dnsx; do
        if command -v "$tool" >/dev/null 2>&1; then
            print_success "$tool is already installed"
            ((tools_installed++))
        else
            print_warning "$tool not found"
            ((tools_missing++))
        fi
    done

    if [[ $tools_missing -gt 0 ]]; then
        print_info "$tools_missing tools missing out of $((tools_installed + tools_missing))"
        print_info "You can install them manually:"
        echo -e "  ${YELLOW}• go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${NC}"
        echo -e "  ${YELLOW}• go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest${NC}"
        echo -e "  ${YELLOW}• go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest${NC}"
        echo -e "  ${YELLOW}• go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest${NC}"
    else
        print_success "All recommended external tools are installed!"
    fi
}


test_installation() {
    print_step "Testing installation..."

    if [[ "$USE_VENV" == true ]]; then
        PYTHON_CMD="$VENV_DIR/bin/python"
    else
        PYTHON_CMD="$PYTHON_BIN"
    fi

    if "$PYTHON_CMD" -c "import network_scanner" 2>/dev/null; then
        print_success "Package import successful"
    else
        print_error "Package import failed"
        return 1
    fi

    if "$PYTHON_CMD" -m network_scanner --help >/dev/null 2>&1; then
        print_success "--help command works"
    else
        print_error "Failed to execute --help"
        return 1
    fi

    if "$PYTHON_CMD" -c "from network_scanner.payloads.exploits import list_exploits; print(list_exploits())" >/dev/null 2>&1; then
        print_success "Exploit import successful"
    else
        print_warning "Exploit import failed (optional dependencies may be missing?)"
    fi

    return 0
}

create_directories() {
    print_step "Creating required directories..."

    mkdir -p "$ROOT_DIR/reports"
    mkdir -p "$ROOT_DIR/logs"
    mkdir -p "$ROOT_DIR/network_scanner/payloads/wordlists"

    print_success "Directories created"
}

show_summary() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${GREEN}                   INSTALLATION SUCCESSFUL!                   ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

    echo -e "\n${WHITE}📁 Installation directory:${NC} $ROOT_DIR"

    if [[ "$USE_VENV" == true ]]; then
        echo -e "${WHITE}🐍 Virtual environment:${NC} $VENV_DIR"
        echo -e "\n${YELLOW}To activate the virtual environment:${NC}"
        echo -e "  ${CYAN}source $VENV_DIR/bin/activate${NC}"

        echo -e "\n${YELLOW}To run BlackScan:${NC}"
        echo -e "  ${CYAN}python scanner.py --help${NC}"
        echo -e "  ${CYAN}python scanner.py -t 192.168.1.1 --authorized --profile quick${NC}"
    else
        echo -e "\n${YELLOW}To run BlackScan:${NC}"
        echo -e "  ${CYAN}python3 scanner.py --help${NC}"
        echo -e "  ${CYAN}python3 scanner.py -t 192.168.1.1 --authorized --profile quick${NC}"
    fi

    echo -e "\n${YELLOW}For the TUI interface:${NC}"
    echo -e "  ${CYAN}python scanner.py --tui${NC}"

    echo -e "\n${YELLOW}For exploits (lab environments only):${NC}"
    echo -e "  ${CYAN}python scanner.py -t 192.168.1.1 --authorized --intrusive-checks --exploit${NC}"

    echo -e "\n${WHITE}📚 Documentation:${NC}"
    echo -e "  • README.md   - User guide"
    echo -e "  • dev.md      - Development notes"

    echo -e "\n${GREEN}Remember:${NC}"
    echo -e "  • Use --authorized to confirm that you have permission"
    echo -e "  • Exploits require --intrusive-checks"
    echo -e "  • Test ONLY on your own machines in a controlled laboratory environment"

    echo -e "\n${CYAN}────────────────────────────────────────────────────────────────────${NC}\n"
}

show_help() {
    cat << EOF
BlackScan - Installation Script

Usage:
    ./install.sh [OPTIONS]

Options:
    --dev           Install development dependencies (ruff, pytest, mypy, etc.)
    --all           Install all optional dependencies (mysql, ssh, http, etc.)
    --no-venv       Install directly into the current environment (not recommended)
    --uninstall     Remove the virtual environment and temporary files
    --help          Show this help message

Examples:
    ./install.sh                # Basic installation
    ./install.sh --dev          # Installation with development tools
    ./install.sh --all          # Full installation with all dependencies
    ./install.sh --no-venv      # Install into the current environment
    ./install.sh --uninstall    # Uninstall BlackScan

Dependencies:
    Python 3.10+                # Required
    pip                         # Required
    git                         # Optional (for development)
    nmap, nuclei, httpx, etc.   # Optional (for external enrichment)

After installation:
    source venv/bin/activate    # Activate the virtual environment
    python scanner.py --help    # View available options
    python scanner.py --tui     # Launch the TUI

EOF
}

uninstall() {
    print_step "Uninstalling BlackScan..."

    if [[ -d "$VENV_DIR" ]]; then
        print_info "Removing virtual environment..."
        rm -rf "$VENV_DIR"
        print_success "Virtual environment removed"
    fi

    if [[ -d "$ROOT_DIR/__pycache__" ]]; then
        print_info "Removing __pycache__ directories..."
        find "$ROOT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        print_success "Temporary files removed"
    fi

    print_success "Uninstallation completed"

    echo -e "\n${YELLOW}The following directories were not removed (user data):${NC}"
    echo -e "  • $ROOT_DIR/reports/"
    echo -e "  • $ROOT_DIR/logs/"
    echo -e "  • $ROOT_DIR/venv/ (if it still exists)"
}

main() {
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
                echo -e "${RED}Unknown option: $1${NC}"
                echo "Use --help to see available options."
                exit 1
                ;;
        esac
    done

    print_header
    check_prerequisites
    detect_os

    if [[ "$OS_TYPE" == "linux" ]]; then
        install_system_dependencies
    else
        print_info "Non-Linux system, skipping system dependency installation"
    fi

    create_directories
    install_python_dependencies
    install_external_tools
    if test_installation; then
        print_success "Installation validated"
    else
        print_warning "Some tests failed, but the installation is probably functional"
    fi
    show_summary
}

main "$@"
```