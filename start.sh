#!/bin/bash

# UFW Web Manager Startup Script
# This script starts the UFW Web Manager with proper permissions

echo "🔥 Starting UFW Web Manager..."
echo "⚠️  This application requires sudo privileges to manage UFW"
echo "📍 Web interface will be available at: http://localhost:5000"
echo "🔐 Default credentials: admin / ufw-admin-2024"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Warning: Not running as root. UFW commands may fail."
    echo "   Consider running with: sudo ./start.sh"
    echo ""
fi

# Check if UFW is installed
if ! command -v ufw &> /dev/null; then
    echo "❌ UFW is not installed. Please install it first:"
    echo "   sudo apt update && sudo apt install ufw"
    exit 1
fi

# Check if Flask is available
if ! python3 -c "import flask" 2>/dev/null; then
    echo "❌ Flask is not installed. Please install it first:"
    echo "   pip3 install flask"
    exit 1
fi

ENV_FILE=".env"
SAMPLE_FILE=".env.sample"

# Prepare environment file
if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$SAMPLE_FILE" ]; then
        echo "📄 No .env found; copying from .env.sample"
        cp "$SAMPLE_FILE" "$ENV_FILE"
    else
        echo "⚠️  No .env or .env.sample present; creating minimal .env"
        cat > "$ENV_FILE" <<EOF
ADMIN_DEFAULT_PASSWORD=ufw-admin-2024
HOST=0.0.0.0
PORT=5000
DEBUG=0
DISABLE_AUTH=0
EOF
    fi
fi

# Load environment variables
set -a
source "$ENV_FILE"
set +a

echo "🔐 Admin default password source: .env (used only if auth.db not yet created)"
if [ "${DISABLE_AUTH}" = "1" ]; then
  echo "⚠️  Authentication DISABLED via DISABLE_AUTH=1 — ensure external protection!"
fi

echo "✅ Starting UFW Web Manager..."
echo "   Press Ctrl+C to stop the server"
echo ""

# Pass host/port/debug via environment (if app.py ever reads them from env later)
export ADMIN_DEFAULT_PASSWORD
export DISABLE_AUTH

python3 app.py
