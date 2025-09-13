# UFW Web Manager

A lightweight web interface for managing UFW (Uncomplicated Firewall) on Ubuntu/Debian systems.

## Features

- 🔥 **Enable / Disable UFW** quickly from the dashboard
- 📋 **Inbound & Outbound Rule Separation** (two clearly labeled sections)
- ➕ **Granular Rule Creation Form:**
    - **Direction:** Inbound or Outbound (maps to UFW default vs `out` rules)
    - **Action:** `allow` or `deny`
    - **Network Protocol (IP Version):** IPv4 only, IPv6 only, or both
    - **Transport Protocol:** TCP, UDP, or any
    - **Port / Service:** Single port (`22`), range (`1000:2000`), or service name (`ssh`, `http`)
    - **Source / Destination IP:** CIDR blocks (`192.168.1.0/24`, `2001:db8::/32`) or single hosts; leave blank for any
    - **Automatic Comment Tagging:** Appends direction + protocol metadata to your custom comment
- 🗑️ **Delete Rules** by number with one click
- 📊 **Live Log Viewer** (tail of UFW-related syslog lines)
- � **Reset Firewall** to defaults (`ufw --force reset`)
- 🔐 **Session-Based Authentication** with configurable timeout

## Requirements

- Python 3.6+
- UFW (Uncomplicated Firewall)
- Sudo privileges
- Flask web framework

## Installation

Recommended (automated):
```bash
# Clone the repository
git clone https://github.com/LokoMoloko98/ufw-web-manager.git
cd ufw-web-manager

# Run the installer (installs ufw, pip, Flask, sets permissions)
sudo ./install.sh

# Start the app
sudo ./start.sh
```
Then browse to: http://localhost:5000

Manual (alternative):
```bash
git clone https://github.com/LokoMoloko98/ufw-web-manager.git
cd ufw-web-manager
sudo apt update
sudo apt install -y ufw python3-pip
pip3 install -r requirements.txt
sudo python3 app.py
```

## Default Credentials

- **Username:** `admin`
- **Password:** `ufw-admin-2024`

**⚠️ Important:** Change the default password after the first login for security! You can do this by generating a new hash and updating the `ADMIN_PASSWORD_HASH` variable in `app.py`.

## Usage

1. Access the web interface at: `http://<server-ip>:5000`
2. Log in (change the default password ASAP)
3. Review current inbound / outbound rules
4. Add a new rule using the form

### Example: Allow IPv4 SSH from a specific subnet
| Field | Value |
|-------|-------|
| Direction | Inbound |
| Action | Allow |
| Network Protocol | IPv4 Only |
| Transport Protocol | TCP |
| Port | 22 |
| Source IP | 203.0.113.0/24 |
| Destination IP | (leave blank) |
| Comment | ssh corp range |

Resulting UFW rule (conceptually):
```
ufw allow from 203.0.113.0/24 to any port 22 proto tcp
```

### Example: Deny outbound DNS over UDP (both stacks)
| Field | Value |
|-------|-------|
| Direction | Outbound |
| Action | Deny |
| Network Protocol | Any |
| Transport Protocol | UDP |
| Port | 53 |
| Source IP | (blank) |
| Destination IP | (blank) |
| Comment | block dns |

Conceptual command:
```
ufw deny out to any port 53 proto udp
```

### Notes
- Leaving Source or Destination blank = `any`
- Setting Network Protocol to IPv4 or IPv6 adjusts implicit address defaults
- Comments are optional; app appends metadata so you can still search later

## Security Notes

- Requires sudo for UFW — consider creating a restricted sudoers entry for the web app user
- Change the default password immediately (edit `ADMIN_PASSWORD_HASH` in `app.py`)
- Use HTTPS (via reverse proxy) if exposing beyond localhost
- Limit network exposure of the management port (e.g., bind to localhost + SSH tunnel)
- Logs may contain IP addresses; handle accordingly

### Suggested sudoers snippet (example)
```
<youruser> ALL=(root) NOPASSWD: /usr/sbin/ufw
```
Then run the app as `<youruser>` without full root if desired.

## File Structure

```
ufw-web-manager/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── README.md          # This file
├── install.sh         # Automated installer
├── start.sh           # Startup script
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

| Issue | Cause | Fix |
|-------|-------|-----|
| Rules not appearing | Browser cached old template | Hard refresh (Ctrl+F5) |
| Outbound rule ignored | Incorrect syntax (earlier versions) | Ensure command order is `ufw <action> out ...` |
| IPv6 rule missing | UFW IPv6 disabled | Check `IPV6=yes` in `/etc/default/ufw` and reload |
| Cannot delete rule | Number changed after add/delete | Refresh list before deleting |
| Permission denied | Running without sudo | Start app with sudo or configure sudoers |

Manual checks:
```
sudo ufw status numbered
sudo grep UFW /var/log/syslog | tail -50
```

If logs are empty, ensure UFW logging is enabled:
```
sudo ufw logging on
```

## Potential Improvements

- Rule editing (inline)
- Bulk operations (multi-select delete)
- Tag-based filtering & search
- Dark mode UI
- Optional app profile picker
- API token authentication
- Dockerfile & systemd unit

Contributions & suggestions welcome — open an issue or PR.

## License

This project is open source. Use at your own risk.

## Author
LokoMoloko98
