#!/bin/bash
set -e

# setup.sh - Dependency installer for Carved C2
# Supports: Debian/Ubuntu (apt), Arch Linux (pacman), Alpine Linux (apk)

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

identify_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        echo "apt"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    elif command -v apk &> /dev/null; then
        echo "apk"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    else
        echo "unknown"
    fi
}

PKG_MANAGER=$(identify_pkg_manager)
echo "[*] Detected package manager: $PKG_MANAGER"

install_system_deps() {
    echo "[*] Installing system dependencies..."
    case $PKG_MANAGER in
        apt)
            apt-get update
            apt-get install -y build-essential mingw-w64 curl git wget certbot
            ;;
        pacman)
            # -Syu is safer on Arch to avoid partial upgrade issues which can break python modules
            pacman -Syu --noconfirm base-devel mingw-w64-gcc curl git wget certbot go
            ;;
        apk)
            apk update
            apk add build-base mingw-w64-gcc curl git wget certbot bash openssl
            ;;
        dnf)
            dnf install -y @development-tools mingw64-gcc curl git wget certbot
            ;;
        *)
            echo "[-] Unsupported package manager. Please install dependencies manually:"
            echo "    build-essential/base-devel, mingw-w64, curl, git, wget, certbot"
            exit 1
            ;;
    esac
}



install_go() {
    if [[ "$PKG_MANAGER" == "pacman" || "$PKG_MANAGER" == "apk" ]]; then
        if ! command -v go &> /dev/null; then
             echo "[*] Installing Go via system package manager..."
             if [ "$PKG_MANAGER" == "pacman" ]; then pacman -S --noconfirm go; fi
             if [ "$PKG_MANAGER" == "apk" ]; then apk add go; fi
        else
            echo "[*] Go already installed"
        fi
        return
    fi

    GO_VER="1.24.11"
    if ! command -v go &> /dev/null; then
        echo "[*] Installing Go ${GO_VER}..."
        wget "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -O go.tgz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf go.tgz
        rm go.tgz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/$(logname)/.profile 2>/dev/null || true
    else
        echo "[*] Go already installed"
    fi
}

install_rust() {
    if ! command -v cargo &> /dev/null; then
        echo "[*] Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"

        if [[ "$PKG_MANAGER" == "apk" ]]; then
            rustup target add x86_64-pc-windows-gnu
        else
            rustup target add x86_64-pc-windows-gnu
        fi
    else
        echo "[*] Rust already installed"
    fi
}

install_zig() {
    if ! command -v zig &> /dev/null; then
        echo "[*] Installing Zig..."
        if [ "$PKG_MANAGER" == "pacman" ]; then
            pacman -S --noconfirm zig
        elif [ "$PKG_MANAGER" == "apk" ]; then
            apk add zig
        elif command -v snap &> /dev/null; then
            snap install zig --classic --beta
        else
            ZIG_VER="0.13.0"
            echo "    Manual install of Zig ${ZIG_VER}..."
            wget "https://ziglang.org/download/${ZIG_VER}/zig-linux-x86_64-${ZIG_VER}.tar.xz" -O zig.tar.xz
            tar -xf zig.tar.xz
            mv "zig-linux-x86_64-${ZIG_VER}" /usr/local/zig
            rm zig.tar.xz
            ln -s /usr/local/zig/zig /usr/local/bin/zig
        fi
    else
        echo "[*] Zig already installed"
    fi
}

install_nim() {
    if ! command -v nim &> /dev/null; then
        echo "[*] Installing Nim..."
        curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y
        export PATH=$PATH:/root/.nimble/bin
        echo 'export PATH=$PATH:$HOME/.nimble/bin' >> ~/.profile
    else
        echo "[*] Nim already installed"
    fi
}

install_system_deps
install_go
install_rust
install_zig
install_nim

echo ""
echo "[+] Setup complete! You may need to restart your shell."
echo "    NOTE: On Alpine/Arch, ensure you are in a bash shell to run build.sh."
