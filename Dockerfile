FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    ufw \
    iptables \
    sudo \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app user and add to necessary groups
RUN useradd -m -u 1000 appuser && \
    usermod -aG sudo appuser && \
    echo 'appuser ALL=(ALL) NOPASSWD: /usr/sbin/ufw' >> /etc/sudoers && \
    echo 'appuser ALL=(ALL) NOPASSWD: /sbin/iptables' >> /etc/sudoers && \
    echo 'appuser ALL=(ALL) NOPASSWD: /bin/systemctl' >> /etc/sudoers

# Set work directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make scripts executable
RUN chmod +x install.sh start.sh docker-deploy.sh

# Change ownership to app user
RUN chown -R appuser:appuser /app

# Switch to app user
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Use install.sh and start.sh
CMD ["./start.sh"]