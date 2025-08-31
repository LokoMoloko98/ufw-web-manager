# UFW Web Manager

A lightweight web interface for managing UFW (Uncomplicated Firewall) on Ubuntu/Debian systems.

## Features

- 🔥 Enable/Disable UFW firewall
- 📋 View current firewall rules
- ➕ Add new firewall rules (allow/deny)
- 🗑️ Delete existing rules
- 📊 View UFW logs
- 🔄 Reset firewall to defaults
- 🔐 Secure web authentication

## Requirements

- Python 3.6+
- UFW (Uncomplicated Firewall)
- Sudo privileges
- Flask web framework

## Installation

1. Clone or download this repository
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   sudo python3 app.py
   ```

## Default Credentials

- **Username:** admin
- **Password:** ufw-admin-2024

**⚠️ Important:** Change the default password after first login for security!

## Usage

1. Access the web interface at `http://localhost:5000`
2. Log in with the default credentials
3. Use the dashboard to manage your UFW firewall:
   - View current status and rules
   - Enable/disable the firewall
   - Add new rules (e.g., `22/tcp`, `80`, `ssh`)
   - View logs for troubleshooting
   - Reset firewall if needed

## Security Notes

- This application requires sudo privileges to execute UFW commands
- Always change the default password
- Consider setting up proper authentication for production use
- Run behind a reverse proxy (nginx/apache) for production deployment

## File Structure

```
ufw-web-manager/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── README.md          # This file
└── templates/         # HTML templates
    ├── login.html     # Login page
    ├── dashboard.html # Main dashboard
    ├── logs.html      # UFW logs viewer
    ├── 404.html       # 404 error page
    └── 500.html       # 500 error page
```

## Configuration

Edit the `CONFIG` dictionary in `app.py` to customize:
- Host and port settings
- Session timeout
- Debug mode

## Troubleshooting

- Ensure UFW is installed: `sudo apt install ufw`
- Check UFW status: `sudo ufw status`
- View UFW logs: `sudo grep UFW /var/log/syslog`
- Ensure the application has sudo privileges

## License

This project is open source. Use at your own risk.

## Author

LokoMoloko98
