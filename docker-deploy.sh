#!/bin/bash

# UFW Web Manager Docker Deployment Script
# This script builds and runs the UFW Web Manager in a Docker container

set -e

echo "🔥🧱 UFW Web Manager - Docker Deployment"
echo "========================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if running as root (required for UFW access)
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root for UFW access"
   echo "   Usage: sudo ./docker-deploy.sh"
   exit 1
fi

# Stop any existing container
echo "🛑 Stopping any existing container..."
docker-compose down 2>/dev/null || true

# Build the image
echo "🔨 Building UFW Web Manager Docker image..."
docker-compose build

# Create necessary directories if they don't exist
echo "📁 Ensuring UFW directories exist..."
mkdir -p /etc/ufw
mkdir -p /var/lib/ufw

# Ensure log files exist
echo "📝 Ensuring UFW log files exist..."
touch /var/log/ufw.log
touch /var/log/kern.log
touch /var/log/syslog

# Set proper permissions for UFW directories and log files
echo "🔧 Setting UFW directory and log file permissions..."
chmod 755 /etc/ufw
chmod 755 /var/lib/ufw
chmod 644 /var/log/ufw.log
chmod 644 /var/log/kern.log
chmod 644 /var/log/syslog

# Ensure UFW config files exist with proper permissions
if [ ! -f /etc/ufw/user.rules ]; then
    touch /etc/ufw/user.rules
fi
if [ ! -f /etc/ufw/user6.rules ]; then
    touch /etc/ufw/user6.rules
fi
chmod 644 /etc/ufw/user.rules /etc/ufw/user6.rules 2>/dev/null || true

# Start the container
echo "🚀 Starting UFW Web Manager container..."
docker-compose up -d

# Wait for container to be ready
echo "⏳ Waiting for container to be ready..."
sleep 5

# Check if container is running
if docker-compose ps | grep -q "running"; then
    echo "✅ UFW Web Manager is now running!"
    echo ""
    echo "🌐 Access your UFW Web Manager at:"
    echo "   http://localhost:5000"
    echo ""
    echo "🔑 Default credentials:"
    echo "   Username: admin"
    echo "   Password: ufw-admin-2024"
    echo ""
    echo "⚠️  IMPORTANT: Change the default password immediately!"
    echo ""
    echo "📊 Container status:"
    docker-compose ps
    echo ""
    echo "📋 To view logs: docker-compose logs -f"
    echo "🛑 To stop: docker-compose down"
else
    echo "❌ Failed to start container. Check logs:"
    docker-compose logs
    exit 1
fi