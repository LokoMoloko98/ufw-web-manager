# 🔥 UFW Web Manager

Minimal, focused web UI for managing UFW (Uncomplicated Firewall) on Ubuntu/Debian.

---
## 1. Why Use It?
Single-file Flask app + small templates that let you:
- 🔥 Toggle UFW on/off
- 📋 See inbound vs outbound rules (separated)
- ➕ Add precise rules (direction, action, IP version, transport protocol, ports, from/to)
- 🗑️ Delete rules quickly by number
- 📊 View latest UFW logs
- ♻️ Reset firewall to defaults
- 🔐 Manage authentication (SQLite + bcrypt) and recover access (token or CLI)
- 🐳 **Docker-ready** with full host UFW access and isolated environment

---
## 2. Quick Start
**Docker (Recommended):**
```bash
git clone https://github.com/LokoMoloko98/ufw-web-manager.git
cd ufw-web-manager
sudo ./docker-deploy.sh
```

See `DOCKER.md` for detailed container setup.

**Manual Installation (Alternative):**
```bash
git clone https://github.com/LokoMoloko98/ufw-web-manager.git
cd ufw-web-manager
sudo ./install.sh
sudo ./start.sh
```

Browse: http://<server-ip>:5000

---
## 3. Features
| Area          | Highlights                                                                                                                      |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| 🔧 Rules       | Direction (in/out), allow/deny, IPv4 / IPv6 / both, TCP/UDP/any, port/service/range, from & to addresses, auto-comment metadata |
| 👁️ Visibility  | Separate inbound/outbound lists + numbered rules for deletion                                                                   |
| 📊 Logs        | Tail of recent UFW syslog entries                                                                                               |
| 🧯 Recovery    | Auto-generated `ADMIN_RESET_TOKEN`, UI Forgot Password flow, CLI reset script                                                   |
| 🔐 Security    | SQLite + bcrypt auth, optional `DISABLE_AUTH=1` for external SSO layer                                                          |
| ♻️ Maintenance | One-click reset (ufw --force reset)                                                                                             |

---
## 4. Authentication & Passwords
| Aspect           | Details                                                                                                           |
| ---------------- | ----------------------------------------------------------------------------------------------------------------- |
| Admin user       | `admin` created automatically on first run (`auth.db`)                                                            |
| Initial password | Use `ADMIN_DEFAULT_PASSWORD` (env / .env). If unset, fallback default is applied and printed. Change immediately. |
| Change (UI)      | Use Change Password link after login                                                                              |
| Change (CLI)     | `python3 reset_admin_password.py 'NewPass123!'` (does NOT recreate DB)                                            |
| Force recreate   | Delete `auth.db` (NOT preferred) then restart with a new `ADMIN_DEFAULT_PASSWORD`                                 |
| Disable auth     | Set `DISABLE_AUTH=1` ONLY behind a trusted reverse proxy / SSO                                                    |

### Forgot Password (Token Flow)
`ADMIN_RESET_TOKEN` enables the UI reset screen. On first fresh `.env` creation the start script auto-generates one (printed once). Steps:
1. Click "Forgot password?".
2. Enter token + new password (>=8 chars) twice.
3. Login with new password.
4. Remove / rotate token in `.env`.

Security: Treat the token like a secret. Do not commit `.env`. Clear it after use.

CLI vs Token:
- CLI: Fast when you have shell access.
- Token: Useful for delegated ops without terminal access.

---
## 5. Configuration
Main runtime config uses environment variables (`.env` auto-created on first start):
| Variable                 | Purpose                                                                  |
| ------------------------ | ------------------------------------------------------------------------ |
| `ADMIN_DEFAULT_PASSWORD` | Initial admin password on first DB creation only                         |
| `ADMIN_RESET_TOKEN`      | Enables Forgot Password UI flow (auto-generated if blank on first start) |
| `DISABLE_AUTH`           | Set to `1` to bypass auth (protect externally!)                          |
| `HOST` / `PORT`          | Listening interface / port                                               |
| `DEBUG`                  | Flask debug mode (avoid in production)                                   |

Edit `CONFIG` in `app.py` if you want to hard-code host/port/debug outside env vars.

---
## 6. Usage

1. Access the web interface at: `http://<server-ip>:5000`
2. Log in (change the default password ASAP)
3. Review current inbound / outbound rules
4. Add a new rule using the form

### Example: Allow IPv4 SSH from a specific subnet
| Field              | Value          |
| ------------------ | -------------- |
| Direction          | Inbound        |
| Action             | Allow          |
| Network Protocol   | IPv4 Only      |
| Transport Protocol | TCP            |
| Port               | 22             |
| Source IP          | 203.0.113.0/24 |
| Destination IP     | (leave blank)  |
| Comment            | ssh corp range |

Resulting UFW rule (conceptually):
```
ufw allow from 203.0.113.0/24 to any port 22 proto tcp
```

### Example: Deny outbound DNS over UDP (both stacks)
| Field              | Value     |
| ------------------ | --------- |
| Direction          | Outbound  |
| Action             | Deny      |
| Network Protocol   | Any       |
| Transport Protocol | UDP       |
| Port               | 53        |
| Source IP          | (blank)   |
| Destination IP     | (blank)   |
| Comment            | block dns |

Resulting UFW rule (conceptually):
```
ufw deny out to any port 53 proto udp
```

Notes:
- Blank source/destination = any
- IPv4 / IPv6 selection influences default address expansions
- Comments are enriched with direction + protocol metadata

---
## 7. Security Guidance
| Topic            | Recommendation                                                            |
| ---------------- | ------------------------------------------------------------------------- |
| Privileges       | Run with sudo or configure sudoers for restricted ufw access              |
| Network exposure | Prefer reverse proxy + TLS; limit binding or firewall the management port |
| Logging          | UFW log lines contain IP data — handle per policy                         |
| Token hygiene    | Remove `ADMIN_RESET_TOKEN` after successful reset                         |
| Auth bypass      | Never expose with `DISABLE_AUTH=1` to the open internet                   |

Suggested sudoers (example):
```
<youruser> ALL=(root) NOPASSWD: /usr/sbin/ufw
```

---
## 8. Troubleshooting
| Issue                 | Cause                       | Fix                                               |
| --------------------- | --------------------------- | ------------------------------------------------- |
| Rules missing         | Cached page                 | Hard refresh (Ctrl+F5)                            |
| Outbound rule ignored | Wrong syntax                | Ensure order: `ufw <action> out ...`              |
| IPv6 rules absent     | IPv6 disabled in UFW        | Set `IPV6=yes` in `/etc/default/ufw`, then reload |
| Delete fails          | Rule numbers shifted        | Refresh status first                              |
| Permission denied     | Not root / no sudoers entry | Run via sudo or configure sudoers                 |

Manual checks:
```
sudo ufw status numbered
sudo grep UFW /var/log/syslog | tail -50
sudo ufw logging on   # enable if empty
```

---
## 9. File Layout
```
├── README.md
├── app.py
├── auth.db
├── install.sh
├── requirements.txt
├── reset_admin_password.py
├── start.sh
└── templates
    ├── 404.html
    ├── 500.html
    ├── change_password.html
    ├── dashboard.html
    ├── forgot_password.html
    ├── login.html
    └── logs.html
```

---
## 10. Potential Improvements
- Inline rule editing
- Bulk rule actions
- Search / filtering & tagging
- Dark mode
- Configuration UI (dynamic token & settings)
- API tokens / external IdP integration

Contributions & suggestions welcome — open an issue or PR.

---
## 11. License
Licensed under the Apache License 2.0 – see `LICENSE` for full text.

## 12. Author
LokoMoloko98
