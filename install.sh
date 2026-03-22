#!/usr/bin/env bash
#
# install.sh — Download and install flagr v3 with all dependencies
#
# Usage:
#   curl -fsSL <raw-url>/install.sh | sudo bash
#   # or
#   chmod +x install.sh && sudo ./install.sh
#
set -uo pipefail

# ── Config ──────────────────────────────────────────────────────────────────
FLAGR_REPO="https://github.com/imattas/Flagr.git"
FLAGR_INSTALL_DIR="/opt/flagr"
FLAGR_BIN_DIR="/usr/local/bin"

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
fail()  { echo -e "${RED}[-]${RESET} $*"; exit 1; }

# ── Root check ──────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root (sudo ./install.sh)"
fi

echo ""
echo -e "${RED}${BOLD}"
cat << 'BANNER'
███████╗██╗      █████╗  ██████╗ ██████╗
██╔════╝██║     ██╔══██╗██╔════╝ ██╔══██╗
█████╗  ██║     ███████║██║  ███╗██████╔╝
██╔══╝  ██║     ██╔══██║██║   ██║██╔══██╗
██║     ███████╗██║  ██║╚██████╔╝██║  ██║
╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
BANNER
echo -e "${RESET}"
echo -e "${BOLD}  Flagr v3 Installer${RESET}"
echo ""

# ── Detect package manager ─────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
elif command -v zypper &>/dev/null; then
    PKG_MGR="zypper"
elif command -v apk &>/dev/null; then
    PKG_MGR="apk"
elif command -v brew &>/dev/null; then
    PKG_MGR="brew"
elif command -v xbps-install &>/dev/null; then
    PKG_MGR="xbps"
elif command -v emerge &>/dev/null; then
    PKG_MGR="portage"
elif command -v nix-env &>/dev/null; then
    PKG_MGR="nix"
else
    warn "No supported package manager found — install dependencies manually"
    PKG_MGR="unknown"
fi

info "Detected package manager: ${BOLD}${PKG_MGR}${RESET}"

# ── Install system packages ────────────────────────────────────────────────
info "Installing system dependencies..."

APT_PKGS=(
    python3 python3-pip python3-dev python3-venv
    build-essential libffi-dev libssl-dev
    libgmp-dev libmpfr-dev libmpc-dev      # gmpy2
    libmagic1                               # python-magic
    libenchant-2-dev                        # pyenchant
    tesseract-ocr                           # pytesseract
    libimage-exiftool-perl                  # exiftool
    binwalk                                 # binwalk unit
    foremost                                # foremost unit
    steghide                                # steghide unit
    poppler-utils                           # pdfinfo, pdfimages
    tcpflow                                 # pcap unit
    unzip                                   # zip unit
    git curl                                # download + git unit
    nodejs                                  # jsfuck unit
    ruby                                    # zsteg (ruby gem)
)

DNF_PKGS=(
    python3 python3-pip python3-devel
    gcc gcc-c++ make libffi-devel openssl-devel
    gmp-devel mpfr-devel libmpc-devel
    file-libs enchant2-devel
    tesseract perl-Image-ExifTool
    binwalk poppler-utils tcpflow
    unzip git curl nodejs ruby
)

PACMAN_PKGS=(
    python python-pip
    base-devel libffi openssl
    gmp mpfr libmpc
    file enchant tesseract
    perl-image-exiftool binwalk poppler
    unzip git curl nodejs ruby
)

ZYPPER_PKGS=(
    python3 python3-pip python3-devel
    gcc gcc-c++ make libffi-devel libopenssl-devel
    gmp-devel mpfr-devel mpc-devel
    file-magic enchant-2-devel
    tesseract-ocr exiftool
    binwalk poppler-tools tcpflow
    unzip git curl nodejs ruby
)

APK_PKGS=(
    python3 py3-pip python3-dev
    gcc g++ make musl-dev libffi-dev openssl-dev
    gmp-dev mpfr-dev mpc1-dev
    file enchant2
    tesseract-ocr perl-image-exiftool
    binwalk poppler-utils
    unzip git curl nodejs ruby
)

BREW_PKGS=(
    python3 libffi openssl gmp mpfr libmpc
    tesseract exiftool binwalk poppler
    unzip git curl node ruby
)

case "${PKG_MGR}" in
    apt)
        apt-get update -qq 2>/dev/null || warn "apt-get update had errors (non-fatal)"
        apt-get install -y -qq "${APT_PKGS[@]}" 2>/dev/null || warn "Some apt packages may not be available"
        ;;
    dnf)
        dnf install -y -q "${DNF_PKGS[@]}" 2>/dev/null || warn "Some dnf packages may not be available"
        ;;
    yum)
        yum install -y -q "${DNF_PKGS[@]}" 2>/dev/null || warn "Some yum packages may not be available"
        ;;
    pacman)
        pacman -Syu --noconfirm --needed "${PACMAN_PKGS[@]}" 2>/dev/null || warn "Some pacman packages may not be available"
        ;;
    zypper)
        zypper install -y "${ZYPPER_PKGS[@]}" 2>/dev/null || warn "Some zypper packages may not be available"
        ;;
    apk)
        apk add --no-cache "${APK_PKGS[@]}" 2>/dev/null || warn "Some apk packages may not be available"
        ;;
    brew)
        brew install "${BREW_PKGS[@]}" 2>/dev/null || warn "Some brew packages may not be available"
        ;;
    xbps)
        xbps-install -Sy python3 python3-pip python3-devel gcc make \
            libffi-devel openssl-devel gmp-devel tesseract-ocr perl-Image-ExifTool \
            binwalk poppler-utils unzip git curl nodejs ruby 2>/dev/null || warn "Some xbps packages may not be available"
        ;;
    portage)
        emerge --noreplace dev-lang/python dev-python/pip sys-devel/gcc dev-libs/libffi \
            dev-libs/openssl dev-libs/gmp app-text/tesseract media-libs/exiftool \
            app-misc/binwalk app-text/poppler app-arch/unzip dev-vcs/git \
            net-misc/curl net-libs/nodejs dev-lang/ruby 2>/dev/null || warn "Some portage packages may not be available"
        ;;
    nix)
        nix-env -iA nixpkgs.python3 nixpkgs.python3Packages.pip nixpkgs.gcc nixpkgs.gnumake \
            nixpkgs.libffi nixpkgs.openssl nixpkgs.gmp nixpkgs.tesseract \
            nixpkgs.exiftool nixpkgs.binwalk nixpkgs.poppler_utils nixpkgs.unzip \
            nixpkgs.git nixpkgs.curl nixpkgs.nodejs nixpkgs.ruby 2>/dev/null || warn "Some nix packages may not be available"
        ;;
    *)
        warn "Skipping system packages — install python3, pip, git, and build tools manually"
        ;;
esac

ok "System packages installed"

# ── Install extra stego tools ──────────────────────────────────────────────
info "Installing additional stego tools..."

# stegsnow
if ! command -v stegsnow &>/dev/null && ! command -v snow &>/dev/null; then
    case "${PKG_MGR}" in
        apt) apt-get install -y -qq stegsnow 2>/dev/null || warn "stegsnow not in repos" ;;
        *)   warn "stegsnow: install manually for your distro" ;;
    esac
fi

# zsteg (Ruby gem)
if command -v gem &>/dev/null; then
    if ! command -v zsteg &>/dev/null; then
        gem install zsteg 2>/dev/null && ok "zsteg installed" || warn "zsteg gem install failed"
    fi
fi

# jsteg (pre-built Go binary)
if ! command -v jsteg &>/dev/null; then
    ARCH=$(uname -m)
    case "${ARCH}" in
        x86_64)  JSTEG_ARCH="amd64" ;;
        aarch64) JSTEG_ARCH="arm64" ;;
        *)       JSTEG_ARCH="" ;;
    esac
    if [[ -n "${JSTEG_ARCH}" ]]; then
        JSTEG_URL="https://github.com/lukechampine/jsteg/releases/download/v0.3.0/jsteg-linux-${JSTEG_ARCH}"
        if curl -fsSL "${JSTEG_URL}" -o "${FLAGR_BIN_DIR}/jsteg" 2>/dev/null; then
            chmod +x "${FLAGR_BIN_DIR}/jsteg"
            ok "jsteg installed"
        else
            warn "jsteg download failed"
        fi
    fi
fi

# ── Download flagr ────────────────────────────────────────────────────────
info "Downloading flagr v3..."

if [[ -d "${FLAGR_INSTALL_DIR}" ]]; then
    info "Updating existing installation at ${FLAGR_INSTALL_DIR}..."
    cd "${FLAGR_INSTALL_DIR}"
    git pull --ff-only origin HEAD 2>/dev/null || git pull origin HEAD || warn "git pull failed, using existing files"
else
    git clone "${FLAGR_REPO}" "${FLAGR_INSTALL_DIR}" \
        || fail "Failed to clone flagr repository"
fi

ok "Flagr downloaded to ${FLAGR_INSTALL_DIR}"

# ── Install Python dependencies via pip ────────────────────────────────────
info "Installing flagr Python package and dependencies..."

FLAGR_SRC="${FLAGR_INSTALL_DIR}"

if [[ ! -f "${FLAGR_SRC}/setup.py" ]]; then
    fail "setup.py not found at ${FLAGR_SRC}/setup.py — bad repo layout?"
fi

pip3 install --break-system-packages "${FLAGR_SRC}" 2>/dev/null \
    || pip3 install "${FLAGR_SRC}" \
    || fail "pip install failed"

ok "Python dependencies installed"

# ── Install binary ────────────────────────────────────────────────────────
info "Installing flagr binary..."

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)   ARCH="x86_64" ;;
    aarch64|arm64)   ARCH="aarch64" ;;
    armv7l)          ARCH="armv7" ;;
    i686|i386)       ARCH="i686" ;;
esac

BINARY_INSTALLED=false

# Try downloading arch-specific binary from GitHub releases
VERSION=$(cat "${FLAGR_INSTALL_DIR}/VERSION" 2>/dev/null || echo "")
if [[ -n "${VERSION}" ]]; then
    RELEASE_URL="https://github.com/imattas/Flagr/releases/download/v${VERSION}/flagr-${ARCH}"
    TMPBIN=$(mktemp)
    if curl -sL --fail --max-time 60 -o "$TMPBIN" "$RELEASE_URL" 2>/dev/null \
        && [[ -s "$TMPBIN" ]] && [[ "$(wc -c < "$TMPBIN")" -gt 1000 ]]; then
        chmod +x "$TMPBIN"
        cp "$TMPBIN" "${FLAGR_BIN_DIR}/flagr" 2>/dev/null && BINARY_INSTALLED=true
    fi
    rm -f "$TMPBIN" 2>/dev/null
fi

# Try local dist
if [[ "$BINARY_INSTALLED" = false && -f "${FLAGR_INSTALL_DIR}/dist/flagr" ]]; then
    cp "${FLAGR_INSTALL_DIR}/dist/flagr" "${FLAGR_BIN_DIR}/flagr" 2>/dev/null && BINARY_INSTALLED=true
fi

# Fallback: use pip-installed entry point or create launcher
if [[ "$BINARY_INSTALLED" = false ]]; then
    FOUND_BIN=$(command -v flagr 2>/dev/null || true)

    if [[ -n "${FOUND_BIN}" && "${FOUND_BIN}" != "${FLAGR_BIN_DIR}/flagr" ]]; then
        ln -sf "${FOUND_BIN}" "${FLAGR_BIN_DIR}/flagr" 2>/dev/null || true
    elif [[ -z "${FOUND_BIN}" ]]; then
        cat > "${FLAGR_BIN_DIR}/flagr" <<'LAUNCHER'
#!/usr/bin/env python3
from flagr.cli import main
main()
LAUNCHER
        chmod +x "${FLAGR_BIN_DIR}/flagr"
    fi
fi

if [[ "$BINARY_INSTALLED" = true ]]; then
    ok "flagr binary installed to ${FLAGR_BIN_DIR}/flagr (${ARCH})"
else
    ok "flagr installed to ${FLAGR_BIN_DIR}/flagr (pip)"
fi

# ── Done ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Flagr v3 installation complete!${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${CYAN}Command:${RESET}   flagr"
echo -e "  ${CYAN}Binary:${RESET}    ${FLAGR_BIN_DIR}/flagr"
echo -e "  ${CYAN}Installed:${RESET} ${FLAGR_INSTALL_DIR}"
echo -e "  ${CYAN}Python:${RESET}    $(python3 --version 2>/dev/null)"
echo ""

# Tool availability check
info "Checking optional tool availability..."
TOOLS=(steghide stegsnow snow zsteg jsteg binwalk foremost tesseract
       exiftool pdfinfo pdfimages tcpflow unzip git node npiet apktool)

FOUND=0
MISSING=0
for tool in "${TOOLS[@]}"; do
    if command -v "${tool}" &>/dev/null; then
        echo -e "  ${GREEN}✓${RESET} ${tool}"
        ((FOUND++))
    else
        echo -e "  ${RED}✗${RESET} ${tool}"
        ((MISSING++))
    fi
done

echo ""
echo -e "  ${GREEN}${FOUND}${RESET} tools found, ${YELLOW}${MISSING}${RESET} optional tools missing"
echo ""
echo -e "  Run ${BOLD}flagr${RESET} to start the interactive shell."
echo -e "  Run ${BOLD}flagr --help${RESET} for usage info."
echo ""
