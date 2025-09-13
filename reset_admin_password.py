#!/usr/bin/env python3
"""
Utility script to reset the admin password for UFW Web Manager.
Usage:
  python3 reset_admin_password.py 'NewStrongPassword!'
If no password argument is provided, you'll be prompted securely.

This script directly updates auth.db. Ensure it is run from the project root.
"""
import os
import sys
import sqlite3
import getpass
import bcrypt
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'auth.db')

if not os.path.exists(DB_PATH):
    print("auth.db not found. The application may not have been started yet. Start it once to create the DB or set ADMIN_DEFAULT_PASSWORD in .env and restart.")
    sys.exit(1)

if len(sys.argv) > 1:
    new_password = sys.argv[1]
else:
    new_password = getpass.getpass('Enter new admin password: ')
    confirm = getpass.getpass('Confirm new admin password: ')
    if new_password != confirm:
        print('Passwords do not match. Aborting.')
        sys.exit(1)

if len(new_password) < 8:
    print('Password must be at least 8 characters.')
    sys.exit(1)

pw_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

conn = sqlite3.connect(DB_PATH)
try:
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = 'admin'")
    row = cur.fetchone()
    if not row:
        print("Admin user not found. Creating new admin user.")
        now = datetime.utcnow().isoformat()
        cur.execute("INSERT INTO users (username, password_hash, created_at, updated_at) VALUES (?,?,?,?)", ('admin', pw_hash, now, now))
    else:
        now = datetime.utcnow().isoformat()
        cur.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE username = 'admin'", (pw_hash, now))
    conn.commit()
    print('Admin password successfully updated.')
except Exception as e:
    print('Error updating password:', e)
    sys.exit(1)
finally:
    conn.close()
