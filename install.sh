#!/bin/bash

# UFW Web Manager Installation Script

echo "🔥 UFW Web Manager Installation"
echo "==============================="
echo ""

# Update package list
echo "📦 Updating package list..."
sudo apt update

# Install UFW if not present
if ! command -v ufw &> /dev/null; then
    echo "📥 Installing UFW..."
    sudo apt install -y ufw
else
    echo "✅ UFW is already installed"
fi

# Install Python pip if not present
if ! command -v pip3 &> /dev/null; then
    echo "📥 Installing Python pip..."
    sudo apt install -y python3-pip
else
    echo "✅ Python pip is already installed"
fi

# Install Flask
echo "📥 Installing Flask..."
pip3 install flask

# Set permissions
echo "🔧 Setting up permissions..."
sudo chown -R root:root /home/moloko/ufw-web-manager/
sudo chmod +x /home/moloko/ufw-web-manager/start.sh

echo ""
echo "✅ Installation completed!"
echo ""
echo "🚀 To start the UFW Web Manager:"
echo "   cd /home/moloko/ufw-web-manager"
echo "   sudo ./start.sh"
echo ""
echo "🌐 Then open your browser to: http://localhost:5000"
echo "🔐 Default login: admin / ufw-admin-2024"
echo ""
echo "⚠️  Remember to change the default password after first login!"
