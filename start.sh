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

echo "✅ Starting UFW Web Manager..."
echo "   Press Ctrl+C to stop the server"
echo ""

# Start the Flask application
python3 app.py
