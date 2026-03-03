#!/bin/bash
# ────────────────────────────────────────────────────────
# Basilisk — Local Build Script
#
# Compiles the Python backend into a standalone binary
# using PyInstaller, then builds the Electron desktop app.
#
# Usage:
#   ./build-desktop.sh          # Build for current platform
#   ./build-desktop.sh linux    # Build for Linux
#   ./build-desktop.sh win      # Build for Windows (on Windows)
#   ./build-desktop.sh mac      # Build for macOS (on macOS)
# ────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "🐍 Basilisk Desktop Build"
echo "========================="
echo ""

# Step 1: Check Python
echo "[1/5] Checking Python environment..."
if [ -f "venv/bin/python" ]; then
    PYTHON="venv/bin/python"
    PIP="venv/bin/pip"
elif [ -f "venv/Scripts/python.exe" ]; then
    PYTHON="venv/Scripts/python.exe"
    PIP="venv/Scripts/pip.exe"
else
    PYTHON="python3"
    PIP="pip3"
fi

echo "  Using: $PYTHON"
$PYTHON --version

# Step 2: Install PyInstaller if missing
echo ""
echo "[2/5] Ensuring PyInstaller is installed..."
$PIP install pyinstaller 2>/dev/null || $PIP install --user pyinstaller

# Step 3: Compile Python backend
echo ""
echo "[3/5] Compiling Python backend with PyInstaller..."
$PYTHON -m PyInstaller basilisk-backend.spec --noconfirm

# Step 4: Copy binary to desktop/bin
echo ""
echo "[4/5] Preparing desktop build..."
mkdir -p desktop/bin

if [ -f "dist/basilisk-backend.exe" ]; then
    cp dist/basilisk-backend.exe desktop/bin/
    echo "  Copied basilisk-backend.exe → desktop/bin/"
elif [ -f "dist/basilisk-backend" ]; then
    cp dist/basilisk-backend desktop/bin/
    chmod +x desktop/bin/basilisk-backend
    echo "  Copied basilisk-backend → desktop/bin/"
else
    echo "  ERROR: basilisk-backend binary not found in dist/"
    exit 1
fi

# Copy license
cp LICENSE desktop/LICENSE.txt 2>/dev/null || echo "MIT License" > desktop/LICENSE.txt

# Prepare icons
mkdir -p desktop/build
cp desktop/src/assets/logo.jpg desktop/build/icon.png 2>/dev/null || true

# Step 5: Build Electron
echo ""
echo "[5/5] Building Electron desktop app..."
cd desktop
npm install

PLATFORM="${1:-}"
case "$PLATFORM" in
    linux)  npx electron-builder --linux  ;;
    win)    npx electron-builder --win    ;;
    mac)    npx electron-builder --mac    ;;
    *)      npx electron-builder          ;;
esac

echo ""
echo "✅ Build complete! Output in desktop/dist/"
ls -la dist/ 2>/dev/null || true
