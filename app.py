#!/usr/bin/env python3
"""
UFW Web Manager - A lightweight web interface for managing UFW firewall
Author: LokoMoloko98
"""

import os
import re
import subprocess
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
import bcrypt
import json
import secrets as pysecrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# --- Authentication / User Store Setup (Flask-Login + bcrypt + SQLite) ---
DB_PATH = os.path.join(os.path.dirname(__file__), 'auth.db')

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_id, username, password_hash):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash

def get_db_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    created = not os.path.exists(DB_PATH)
    conn = get_db_conn()
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()
        # Ensure single admin user exists
        c.execute('SELECT id, username, password_hash FROM users WHERE username = ?', ('admin',))
        row = c.fetchone()
        if not row:
            default_password = os.getenv('ADMIN_DEFAULT_PASSWORD', 'ufw-admin-2024')
            pw_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            now = datetime.utcnow().isoformat()
            c.execute('INSERT INTO users (username, password_hash, created_at, updated_at) VALUES (?,?,?,?)', ('admin', pw_hash, now, now))
            conn.commit()
            print('[AUTH] Created default admin user (username=admin). Please change the password asap.')
        elif created:
            print('[AUTH] Existing database detected but newly created file; verify integrity.')
    finally:
        conn.close()

def fetch_user_by_username(username):
    conn = get_db_conn()
    try:
        c = conn.cursor()
        c.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
        row = c.fetchone()
        if row:
            return User(row[0], row[1], row[2])
        return None
    finally:
        conn.close()

def fetch_user_by_id(user_id):
    conn = get_db_conn()
    try:
        c = conn.cursor()
        c.execute('SELECT id, username, password_hash FROM users WHERE id = ?', (user_id,))
        row = c.fetchone()
        if row:
            return User(row[0], row[1], row[2])
        return None
    finally:
        conn.close()

def update_user_password(user_id, new_plain_password):
    conn = get_db_conn()
    try:
        c = conn.cursor()
        new_hash = bcrypt.hashpw(new_plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        now = datetime.utcnow().isoformat()
        c.execute('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', (new_hash, now, user_id))
        conn.commit()
    finally:
        conn.close()

@login_manager.user_loader
def load_user(user_id):
    return fetch_user_by_id(user_id)

# Template filter for parsing UFW rules
@app.template_filter('parse_rule')
def parse_rule_filter(rule_text):
    """Parse UFW rule text into components for table display"""
    if not rule_text:
        return {}
    
    # Default values
    parsed = {
        'action': 'allow',
        'port': None,
        'protocol': None,
        'from_addr': None,
        'to_addr': None,
        'version': None
    }
    
    # Extract action (ALLOW, DENY, REJECT)
    if 'ALLOW' in rule_text.upper():
        parsed['action'] = 'allow'
    elif 'DENY' in rule_text.upper():
        parsed['action'] = 'deny' 
    elif 'REJECT' in rule_text.upper():
        parsed['action'] = 'reject'
    
    # Extract protocol (tcp, udp)
    protocol_match = re.search(r'\b(tcp|udp)\b', rule_text, re.IGNORECASE)
    if protocol_match:
        parsed['protocol'] = protocol_match.group(1).lower()
    
    # Extract port numbers
    port_match = re.search(r'\b(\d+(?:/\w+)?)\b', rule_text)
    if port_match:
        parsed['port'] = port_match.group(1)
    
    # Extract IP version (look for IPv6 indicators)
    if '::' in rule_text or 'v6' in rule_text:
        parsed['version'] = 'IPv6'
    elif re.search(r'\b\d+\.\d+\.\d+\.\d+\b', rule_text):
        parsed['version'] = 'IPv4'
    
    # Extract from/to addresses
    parts = rule_text.split()
    for i, part in enumerate(parts):
        if part.upper() == 'FROM' and i + 1 < len(parts):
            parsed['from_addr'] = parts[i + 1]
        elif part.upper() == 'TO' and i + 1 < len(parts):
            parsed['to_addr'] = parts[i + 1]
    
    return parsed

# Configuration
CONFIG = {
    'HOST': '0.0.0.0',
    'PORT': 5000,
    'DEBUG': False,
    'SESSION_TIMEOUT': 30  # minutes
}

# Legacy constants removed; credentials now stored in SQLite. Default password may be provided via ADMIN_DEFAULT_PASSWORD env var.

class UFWManager:
    """Class to handle UFW operations"""
    
    @staticmethod
    def run_command(command_list):
        """Execute UFW command safely by passing a list of arguments"""
        try:
            # Allow backwards compatibility: accept either list (preferred) or string (shell pipeline)
            if isinstance(command_list, str):
                result = subprocess.run(
                    command_list,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=True
                )
            else:
                result = subprocess.run(
                    command_list,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            return {
                'success': result.returncode == 0,
                'output': result.stdout.strip(),
                'error': result.stderr.strip()
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': '', 'error': 'Command timeout'}
        except Exception as e:
            return {'success': False, 'output': '', 'error': str(e)}
    
    @staticmethod
    def get_status():
        """Get UFW status and rules, separated by direction"""
        result = UFWManager.run_command(['sudo', 'ufw', 'status', 'numbered'])
        if not result['success']:
            return {
                'active': False, 
                'inbound_rules': [], 
                'outbound_rules': [],
                'numbered_rules': [],
                'error': result['error']
            }
        
        output = result['output']
        active = 'Status: active' in output
        
        inbound_rules = []
        outbound_rules = []
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if not line.startswith('['):
                continue
            
            match = re.match(r'\[\s*(\d+)\s*\]\s*(.*)', line)
            if not match:
                continue
                
            rule_number = match.group(1)
            rule_text = match.group(2).strip()
            
            if not rule_text:
                continue
            
            rule_data = {'number': rule_number, 'rule': rule_text}
            
            # Determine direction based on rule text
            # A more robust check for outbound rules
            if 'ALLOW OUT' in rule_text or 'DENY OUT' in rule_text or 'REJECT OUT' in rule_text:
                outbound_rules.append(rule_data)
            else:
                inbound_rules.append(rule_data)

        
        # Create a unified numbered_rules list (legacy compatibility & delete operations) sorted by rule number
        combined = inbound_rules + outbound_rules
        try:
            combined_sorted = sorted(combined, key=lambda r: int(r['number']))
        except Exception:
            combined_sorted = combined  # Fallback if unexpected format

        return {
            'active': active,
            'inbound_rules': inbound_rules,
            'outbound_rules': outbound_rules,
            'numbered_rules': combined_sorted,
            'error': None
        }
    
    @staticmethod
    def enable():
        """Enable UFW"""
        return UFWManager.run_command(['sudo', 'ufw', '--force', 'enable'])
    
    @staticmethod
    def disable():
        """Disable UFW"""
        return UFWManager.run_command(['sudo', 'ufw', 'disable'])
    
    @staticmethod
    def add_rule(direction, action, net_protocol, transport_protocol, port, source_ip='any', dest_ip='any', comment=None):
        """Add a comprehensive UFW rule with direction and full from/to syntax"""
        # Validate input
        if direction not in ['in', 'out']:
            return {'success': False, 'error': 'Invalid direction'}
            
        if action not in ['allow', 'deny']:
            return {'success': False, 'error': 'Invalid action'}
        
        if net_protocol not in ['any', 'ipv4', 'ipv6']:
            return {'success': False, 'error': 'Invalid network protocol. Must be any, ipv4, or ipv6'}
            
        if transport_protocol not in ['any', 'tcp', 'udp']:
            return {'success': False, 'error': 'Invalid transport protocol. Must be any, tcp, or udp'}
        
        # Validate port
        if not re.match(r'^[a-zA-Z0-9\:_-]+$', port):
            return {'success': False, 'error': 'Invalid port format'}
        
        # Build UFW command: order must be `ufw <action> [out]` (ufw syntax expects action first)
        command_parts = ['sudo', 'ufw', action]

        # Add direction (ONLY for outbound; inbound is default)
        if direction == 'out':
            command_parts.append('out')
        
        # Handle source - always specify from
        if source_ip == 'any':
            if net_protocol == 'ipv6':
                source = '::/0'
            else:
                source = '0.0.0.0/0'
        else:
            source = source_ip
        
        # Handle destination - always specify to  
        if dest_ip == 'any':
            dest = 'any'
        else:
            dest = dest_ip
        
        # ALWAYS use from/to syntax
        command_parts.extend(['from', source, 'to', dest])
        
        # Add port specification
        command_parts.extend(['port', port])
        
        # Add protocol specification
        if transport_protocol != 'any':
            command_parts.extend(['proto', transport_protocol])
        
        # Add comment if provided
        if comment:
            direction_comment = " (Outbound)" if direction == 'out' else " (Inbound)"
            proto_comment = f" ({net_protocol.upper()}" + (f"/{transport_protocol.upper()}" if transport_protocol != 'any' else "") + ")"
            comment_text = f"{comment}{direction_comment}{proto_comment}"
            command_parts.extend(['comment', comment_text])
        
        # Debug: Print the command being executed
        print(f"DEBUG: Executing UFW command: {' '.join(command_parts)}")
        
        result = UFWManager.run_command(command_parts)
        print(f"DEBUG: UFW command result: {result}")
        return result
    
    @staticmethod
    def delete_rule(rule_number):
        """Delete a UFW rule by number"""
        try:
            rule_num = int(rule_number)
            if rule_num <= 0:
                return {'success': False, 'error': 'Rule number must be positive'}
            
            # First check if the rule exists by getting current status
            status = UFWManager.get_status()
            if not status.get('numbered_rules'):
                return {'success': False, 'error': 'No rules to delete'}
            
            # Find the rule to confirm its existence
            rule_exists = any(r.get('number') == str(rule_num) for r in status.get('numbered_rules', []))
            if not rule_exists:
                return {'success': False, 'error': f'Rule {rule_num} not found'}
            
            # Use subprocess to auto-confirm the deletion prompt by piping 'yes'
            p1 = subprocess.Popen(['yes'], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(
                ['sudo', 'ufw', 'delete', str(rule_num)],
                stdin=p1.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
            
            output, error = p2.communicate(timeout=10)
            
            return {
                'success': p2.returncode == 0,
                'output': output.strip(),
                'error': error.strip()
            }
            
        except ValueError:
            return {'success': False, 'error': 'Invalid rule number'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def reset():
        """Reset UFW to defaults"""
        return UFWManager.run_command(['sudo', 'ufw', '--force', 'reset'])
    
    @staticmethod
    def get_logs():
        """Get UFW logs"""
        # Use shell pipeline via string for grep + tail (run_command handles string with shell=True)
        result = UFWManager.run_command('sudo grep UFW /var/log/syslog | tail -50')
        if result['success']:
            return result['output'].split('\n')
        return []

def login_required(f):
    """Lightweight auth decorator wrapping Flask-Login; supports optional bypass for external auth.
    Set DISABLE_AUTH=1 environment variable to bypass (for reverse proxy / Authentik integration)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if os.getenv('DISABLE_AUTH') == '1':
            return f(*args, **kwargs)
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

@app.route('/')
def index():
    """Redirect to dashboard or login"""
    # Legacy session object removed; rely on Flask-Login state or DISABLE_AUTH bypass
    if os.getenv('DISABLE_AUTH') == '1' or current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/healthz')
def health_check():
    """Health check endpoint for Docker"""
    return {'status': 'healthy', 'service': 'ufw-web-manager'}, 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    if os.getenv('DISABLE_AUTH') == '1':
        flash('Auth disabled by environment; bypassing login.', 'warning')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = fetch_user_by_username(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            login_user(user)
            flash('Successfully logged in!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    reset_enabled = bool(os.getenv('ADMIN_RESET_TOKEN'))
    return render_template('login.html', reset_enabled=reset_enabled)

@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
    flash('Logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')
        if not new_pw or len(new_pw) < 8:
            flash('New password must be at least 8 characters.', 'error')
            return redirect(url_for('change_password'))
        if new_pw != confirm_pw:
            flash('Password confirmation does not match.', 'error')
            return redirect(url_for('change_password'))
        # Re-fetch user
        user = fetch_user_by_id(current_user.id)
        if not user or not bcrypt.checkpw(current_pw.encode('utf-8'), user.password_hash.encode('utf-8')):
            flash('Current password incorrect.', 'error')
            return redirect(url_for('change_password'))
        update_user_password(user.id, new_pw)
        flash('Password updated successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Admin password reset via one-time token defined by ADMIN_RESET_TOKEN env var.
    This is intentionally simple (no email). If token is not set server-side, feature is disabled."""
    if os.getenv('DISABLE_AUTH') == '1':
        flash('Auth is disabled; password reset not required.', 'warning')
        return redirect(url_for('dashboard'))

    reset_token_env = os.getenv('ADMIN_RESET_TOKEN')
    if not reset_token_env:
        flash('Password reset is not enabled on this deployment.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        provided_token = request.form.get('token', '').strip()
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')
        if provided_token != reset_token_env:
            flash('Invalid reset token.', 'error')
            return redirect(url_for('forgot_password'))
        if not new_pw or len(new_pw) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return redirect(url_for('forgot_password'))
        if new_pw != confirm_pw:
            flash('Password confirmation mismatch.', 'error')
            return redirect(url_for('forgot_password'))
        # Update admin user
        conn = get_db_conn()
        try:
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE username='admin'")
            row = c.fetchone()
            if not row:
                flash('Admin user missing; start application to initialize DB.', 'error')
                return redirect(url_for('login'))
            admin_id = row[0]
            update_user_password(admin_id, new_pw)
            flash('Admin password reset successfully. You can now log in.', 'success')
            return redirect(url_for('login'))
        finally:
            conn.close()
    return render_template('forgot_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    status = UFWManager.get_status()
    return render_template('dashboard.html', status=status)

@app.route('/api/status')
@login_required
def api_status():
    """API endpoint for UFW status"""
    return jsonify(UFWManager.get_status())

@app.route('/api/toggle', methods=['POST'])
@login_required
def api_toggle():
    """API endpoint to enable/disable UFW"""
    action = request.json.get('action')
    
    if action == 'enable':
        result = UFWManager.enable()
    elif action == 'disable':
        result = UFWManager.disable()
    else:
        return jsonify({'success': False, 'error': 'Invalid action'})
    
    return jsonify(result)

@app.route('/api/add_rule', methods=['POST'])
@login_required
def api_add_rule():
    """API endpoint to add a comprehensive rule"""
    data = request.json
    direction = data.get('direction', 'in')
    action = data.get('action')
    net_protocol = data.get('net_protocol', 'any')
    transport_protocol = data.get('transport_protocol', 'any')
    port = data.get('port')
    source_ip = data.get('source_ip', 'any')
    dest_ip = data.get('dest_ip', 'any')
    comment = data.get('comment', '')
    
    if not action or not port:
        return jsonify({'success': False, 'error': 'Action and port are required'})
    
    result = UFWManager.add_rule(
        direction=direction,
        action=action,
        net_protocol=net_protocol,
        transport_protocol=transport_protocol,
        port=port,
        source_ip=source_ip,
        dest_ip=dest_ip,
        comment=comment
    )
    return jsonify(result)

@app.route('/api/delete_rule', methods=['POST'])
@login_required
def api_delete_rule():
    """API endpoint to delete a rule"""
    rule_number = request.json.get('rule_number')
    
    if not rule_number:
        return jsonify({'success': False, 'error': 'Missing rule number'})
    
    result = UFWManager.delete_rule(rule_number)
    return jsonify(result)

@app.route('/api/reset', methods=['POST'])
@login_required
def api_reset():
    """API endpoint to reset UFW"""
    result = UFWManager.reset()
    return jsonify(result)

@app.route('/logs')
@login_required
def logs():
    """UFW logs page"""
    log_entries = UFWManager.get_logs()
    return render_template('logs.html', logs=log_entries)

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Check if running as root (required for UFW commands)
    if os.geteuid() != 0:
        print("Warning: This application requires sudo privileges to manage UFW.")
        print("Consider running with sudo or setting up sudoers configuration.")
    # Initialize authentication database
    init_db()

    print(f"Starting UFW Web Manager on {CONFIG['HOST']}:{CONFIG['PORT']}")
    if os.getenv('DISABLE_AUTH') == '1':
        print('[AUTH] Authentication DISABLED via DISABLE_AUTH=1 (suitable only behind trusted reverse proxy).')
    else:
        print("[AUTH] Using SQLite user store with bcrypt. Default admin user ensured (username=admin). Set ADMIN_DEFAULT_PASSWORD env var before first run to override.")
    
    app.run(
        host=CONFIG['HOST'],
        port=CONFIG['PORT'],
        debug=CONFIG['DEBUG']
    )
