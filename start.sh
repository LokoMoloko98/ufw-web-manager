#!/bin/bash

# UFW Web Manager Startup Script
# This script starts the UFW Web Manager with proper permissions

echo "🔥 Starting UFW Web Manager..."
echo "⚠️  This application requires sudo privileges to manage UFW"
echo "📍 Web interface default: http://localhost:5000 (override HOST/PORT in .env)"
echo "🔐 Admin user will be created on first run (set ADMIN_DEFAULT_PASSWORD in .env beforehand)"
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

# Determine Python interpreter (prefer virtual environment)
PYTHON_BIN="python3"
if [ -d ".venv" ] && [ -x ".venv/bin/python" ]; then
    PYTHON_BIN=".venv/bin/python"
    echo "🐍 Using virtual environment interpreter: $PYTHON_BIN"
fi

# Check if Flask is available in interpreter
if ! "$PYTHON_BIN" -c "import flask" 2>/dev/null; then
    echo "❌ Flask not found in $PYTHON_BIN. Run ./install.sh first."; exit 1; fi

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
ADMIN_RESET_TOKEN=
EOF
    fi
    # If ADMIN_RESET_TOKEN is empty or unset in the new file, generate a random one
    if grep -q '^ADMIN_RESET_TOKEN=' "$ENV_FILE"; then
        current_token=$(grep '^ADMIN_RESET_TOKEN=' "$ENV_FILE" | head -1 | cut -d'=' -f2-)
        if [ -z "$current_token" ]; then
            new_token=$(openssl rand -hex 24 2>/dev/null || python3 - <<'PY'
import secrets
print(secrets.token_hex(24))
PY
)
            # Escape forward slashes for sed portability
            esc_token=$(printf '%s' "$new_token" | sed 's:/:\\/:g')
            sed -i "s/^ADMIN_RESET_TOKEN=.*/ADMIN_RESET_TOKEN=$esc_token/" "$ENV_FILE"
            echo "🔐 Generated ADMIN_RESET_TOKEN (display once): $new_token"
            echo "   Store this somewhere safe. Remove or change it after password reset." 
        fi
    else
        # No line present; append
        new_token=$(openssl rand -hex 24 2>/dev/null || python3 - <<'PY'
import secrets
print(secrets.token_hex(24))
PY
)
        echo "ADMIN_RESET_TOKEN=$new_token" >> "$ENV_FILE"
        echo "🔐 Generated ADMIN_RESET_TOKEN (display once): $new_token"
        echo "   Store this somewhere safe. Remove or change it after password reset." 
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

# Display credential hints (do not show actual password hash, only configured defaults)
echo "👤 Admin username: admin"
if [ -n "${ADMIN_DEFAULT_PASSWORD}" ]; then
    echo "🔑 Default admin password (only if DB first-run): ${ADMIN_DEFAULT_PASSWORD}"
else
    echo "🔑 Default admin password: (not set in environment; using internal fallback if first run)"
fi
if [ -n "${ADMIN_RESET_TOKEN}" ]; then
    echo "🧯 Password reset token ENABLED (Forgot password link active)"
    echo "   ADMIN_RESET_TOKEN=${ADMIN_RESET_TOKEN}"
else
    echo "🧯 Password reset token not set (you can add ADMIN_RESET_TOKEN in .env to enable UI reset)"
fi
echo ""

# Export key vars (future-proofing)
export ADMIN_DEFAULT_PASSWORD DISABLE_AUTH ADMIN_RESET_TOKEN

"$PYTHON_BIN" app.py
