#!/bin/bash

# UFW Web Manager Installation Script

echo "🔥 UFW Web Manager Installation"
echo "==============================="
echo ""

# Determine project root (directory where script resides)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "📂 Project root: $SCRIPT_DIR"

# Update package list
echo "📦 Updating package list..."
sudo apt update -y >/dev/null

# Install UFW if not present
if ! command -v ufw &> /dev/null; then
    echo "📥 Installing UFW..."
    sudo apt install -y ufw
else
    echo "✅ UFW is already installed"
fi

# Ensure Python tooling (pip + venv)
echo "🐍 Ensuring Python tooling (python3-pip python3-venv)..."
sudo apt install -y python3-pip python3-venv >/dev/null || { echo "❌ Failed to install python tooling"; exit 1; }

# Virtual environment setup unless SKIP_VENV=1
if [ "${SKIP_VENV}" = "1" ]; then
    echo "⚠️  SKIP_VENV=1 set — will install into system environment (not recommended).";
    PIP_BIN="pip3";
else
    VENV_DIR="$SCRIPT_DIR/.venv"
    if [ ! -d "$VENV_DIR" ]; then
        echo "🧪 Creating virtual environment at $VENV_DIR";
        python3 -m venv "$VENV_DIR" || { echo "❌ venv creation failed"; exit 1; }
    fi
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    PIP_BIN="pip"
    echo "✅ Using virtual environment: $VENV_DIR"
fi

echo "📥 Upgrading pip..."
$PIP_BIN install --upgrade pip >/dev/null 2>&1 || echo "⚠️  pip upgrade skipped"

echo "📥 Installing dependencies from requirements.txt ..."
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    $PIP_BIN install -r "$SCRIPT_DIR/requirements.txt" || { echo "❌ Dependency installation failed"; exit 1; }
else
    echo "⚠️  requirements.txt missing; installing Flask only"
    $PIP_BIN install Flask
fi

# Ensure start script executable
echo "🔧 Ensuring start script is executable..."
chmod +x "$SCRIPT_DIR/start.sh"

echo ""
echo "✅ Installation completed!"
echo ""
echo "🚀 To start the UFW Web Manager:"
echo "   cd $SCRIPT_DIR"
echo "   sudo ./start.sh   # (or ./start.sh if your user has needed sudo rights for ufw)"
echo ""
echo "🌐 Then open your browser to: http://localhost:5000"
echo "🔐 Default admin user will be auto-created on first run (set ADMIN_DEFAULT_PASSWORD in .env first)."
echo ""
echo "⚠️  Remember to change the default password after first login!"
