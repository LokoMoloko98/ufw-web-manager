#!/bin/bash

# UFW-Docker Installation Script
# This script installs chaifeng's ufw-docker for proper Docker-UFW integration

echo "🐳 Installing UFW-Docker Integration"
echo "===================================="
echo ""

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "📂 Script directory: $SCRIPT_DIR"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker not found. Installing Docker first..."
    
    # Update package list
    sudo apt update -y >/dev/null
    
    # Install Docker
    sudo apt install -y docker.io docker-compose
    
    # Start and enable Docker service
    sudo systemctl start docker
    sudo systemctl enable docker
    
    # Add current user to docker group
    sudo usermod -aG docker $USER
    
    echo "✅ Docker installed successfully"
    echo "ℹ️  You may need to log out and back in for Docker group changes to take effect"
else
    echo "✅ Docker is already installed"
fi

# Check if UFW is installed and active
if ! command -v ufw &> /dev/null; then
    echo "❌ UFW not found. Please install UFW first using the main install.sh script"
    exit 1
fi

echo "📥 Downloading ufw-docker..."

# Create a temporary directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Download ufw-docker
wget -q https://raw.githubusercontent.com/chaifeng/ufw-docker/master/ufw-docker -O ufw-docker || {
    echo "❌ Failed to download ufw-docker"
    rm -rf "$TMP_DIR"
    exit 1
}

# Make it executable
chmod +x ufw-docker

# Install to /usr/local/bin
echo "📦 Installing ufw-docker to /usr/local/bin..."
sudo mv ufw-docker /usr/local/bin/ || {
    echo "❌ Failed to install ufw-docker"
    rm -rf "$TMP_DIR"
    exit 1
}

# Clean up
cd "$SCRIPT_DIR"
rm -rf "$TMP_DIR"

echo "✅ ufw-docker installed successfully"

# Check UFW status and install ufw-docker rules
echo "🔧 Setting up ufw-docker integration..."

if ufw status | grep -q "Status: active"; then
    echo "✅ UFW is active, installing ufw-docker rules..."
    
    # Install ufw-docker rules (this modifies UFW configuration for Docker compatibility)
    sudo ufw-docker install || {
        echo "⚠️  Failed to install ufw-docker rules. You may need to run 'sudo ufw-docker install' manually."
    }
    
    echo "🔄 Restarting UFW to apply changes..."
    sudo systemctl restart ufw || sudo service ufw restart
    
    echo "✅ ufw-docker integration completed"
    echo ""
    echo "🎉 You can now use ufw-docker commands like:"
    echo "   sudo ufw-docker allow container_name 80/tcp"
    echo "   sudo ufw-docker list container_name"
    echo "   sudo ufw-docker delete allow container_name 80/tcp"
else
    echo "⚠️  UFW is not active. Please enable UFW first, then run:"
    echo "   sudo ufw-docker install"
    echo "   sudo systemctl restart ufw"
fi

echo ""
echo "📖 For more information about ufw-docker, visit:"
echo "   https://github.com/chaifeng/ufw-docker"