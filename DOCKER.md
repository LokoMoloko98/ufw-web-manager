# UFW Web Manager - Docker Documentation

## 🐳 Docker Deployment

This directory contains everything needed to run UFW Web Manager in a Docker container with full access to the host's UFW firewall.

### 📋 Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- Root access (required for UFW management)
- UFW installed on the host system

### 🚀 Quick Start

1. **Clone and navigate to the project:**
   ```bash
   git clone <your-repo>
   cd ufw-web-manager
   ```

2. **Deploy with one command:**
   ```bash
   sudo ./docker-deploy.sh
   ```

3. **Access the web interface:**
   - URL: http://localhost:5000
   - Default username: `admin`
   - Default password: `admin123`

### 🔧 Manual Deployment

If you prefer manual control:

```bash
# Build the image
sudo docker-compose build

# Start the container
sudo docker-compose up -d

# Check status
sudo docker-compose ps

# View logs
sudo docker-compose logs -f

# Stop the container
sudo docker-compose down
```

### 🛡️ Security Configuration

**Important security considerations:**

1. **Change default password immediately** after first login
2. **Use strong passwords** for the admin account
3. **Consider firewall rules** for port 5000
4. **Use HTTPS** in production (configure reverse proxy)

### 🔗 Container Architecture

The container requires special privileges to manage UFW:

- **Network mode**: `host` for direct network access
- **Privileged mode**: Required for iptables manipulation
- **Capabilities**: `NET_ADMIN`, `NET_RAW`, `SYS_MODULE`
- **Volume mounts**: UFW configuration directories
- **User**: Runs as `appuser` with sudo privileges for UFW commands

### 🔄 Environment Variables

Configure via `docker-compose.yml`:

```yaml
environment:
  - FLASK_ENV=production
  - ADMIN_DEFAULT_PASSWORD=your-secure-password
  - HOST=0.0.0.0
  - PORT=5000
```

### 📊 Monitoring

**Health check:**
```bash
sudo docker-compose ps
```

**View logs:**
```bash
sudo docker-compose logs -f
```

**Container shell access:**
```bash
sudo docker-compose exec ufw-web-manager bash
```

### 🌐 Production Deployment

For production use, consider:

1. **Reverse Proxy**: Use Nginx/Traefik with SSL
2. **Authentication**: Integrate with existing auth systems
3. **Backup**: Regular backups of UFW rules
4. **Monitoring**: Container and application monitoring
5. **Updates**: Regular security updates

### 🔧 Troubleshooting

**Common issues:**

1. **Permission denied**: Ensure running with `sudo`
2. **UFW not found**: Install UFW on host system
3. **Port conflicts**: Change port in docker-compose.yml
4. **Container won't start**: Check logs with `docker-compose logs`

### 📝 File Structure

```
ufw-web-manager/
├── Dockerfile              # Container definition
├── docker-compose.yml      # Service configuration
├── docker-deploy.sh        # Deployment script
├── .dockerignore           # Docker ignore rules
├── app.py                  # Main application
├── requirements.txt        # Python dependencies
└── templates/              # Web templates
    ├── base.html
    ├── dashboard.html
    └── ...
```

### 🔄 Updates

To update the application:

```bash
# Pull latest changes
git pull

# Rebuild and restart
sudo docker-compose down
sudo docker-compose build
sudo docker-compose up -d
```

---

🔥🧱 **UFW Web Manager** - Secure, containerized firewall management!