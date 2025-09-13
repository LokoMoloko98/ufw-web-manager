# UFW Web Manager

A lightweight web interface for managing UFW (Uncomplicated Firewall) on Ubuntu/Debian systems.

## Features

- 🔥 **Enable/Disable UFW:** Quickly activate or deactivate the firewall.
- 📋 **View Rules:** See all current UFW rules in a clean, numbered list.
- ➕ **Comprehensive Rule Creation:** Add rules with granular control:
  - **Action:** Allow or Deny.
  - **IP Version:** IPv4, IPv6, or both.
  - **Protocol:** TCP, UDP, or any.
  - **Port:** Specify single ports, ranges (e.g., `1000:2000`), or service names (e.g., `ssh`).
  - **Source/Destination:** Define specific source and destination IP addresses or subnets (CIDR).
- 🗑️ **Delete Rules:** Easily delete rules by their number.
- 📊 **View Logs:** See the latest UFW log entries for troubleshooting.
- 🔄 **Reset Firewall:** Reset UFW to its default state.
- 🔐 **Secure Login:** Protects the interface with a username and password.

## Requirements

- Python 3.6+
- UFW (Uncomplicated Firewall)
- Sudo privileges
- Flask web framework

## Installation

1.  Clone or download this repository.
2.  Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Run the application with sudo privileges:
    ```bash
    sudo python3 app.py
    ```

## Default Credentials

- **Username:** `admin`
- **Password:** `ufw-admin-2024`

**⚠️ Important:** Change the default password after the first login for security! You can do this by generating a new hash and updating the `ADMIN_PASSWORD_HASH` variable in `app.py`.

## Usage

1.  Access the web interface at `http://<your-server-ip>:5000`.
2.  Log in with the default credentials.
3.  Use the dashboard to manage your UFW firewall:
    -   **View Status:** See if the firewall is active and view all existing rules.
    -   **Toggle Firewall:** Enable or disable UFW with a single click.
    -   **Add Rules:** Use the comprehensive form to create detailed rules. For example, to allow incoming HTTP traffic on port 80 from any IPv4 address:
        -   **Action:** `Allow`
        -   **Network Protocol:** `IPv4 Only`
        -   **Transport Protocol:** `TCP`
        -   **Port:** `80`
        -   Leave Source and Destination IP empty for `any`.
    -   **Delete Rules:** Click the delete button next to any rule in the list.
    -   **View Logs:** Navigate to the logs page to see recent firewall activity.

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
