#!/usr/bin/env python3
"""
UFW Web Manager - A lightweight web interface for managing UFW firewall
Author: LokoMoloko98
"""

import os
import re
import subprocess
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Configuration
CONFIG = {
    'HOST': '0.0.0.0',
    'PORT': 5000,
    'DEBUG': False,
    'SESSION_TIMEOUT': 30  # minutes
}

# Default admin credentials (change these!)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD_HASH = generate_password_hash('ufw-admin-2024')

class UFWManager:
    """Class to handle UFW operations"""
    
    @staticmethod
    def run_command(command):
        """Execute UFW command safely"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
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
        """Get UFW status and rules"""
        result = UFWManager.run_command('sudo ufw status verbose')
        if not result['success']:
            return {'active': False, 'rules': [], 'error': result['error']}
        
        output = result['output']
        active = 'Status: active' in output
        
        rules = []
        lines = output.split('\n')
        for line in lines:
            if '->' in line or 'ALLOW' in line or 'DENY' in line:
                rules.append(line.strip())
        
        return {'active': active, 'rules': rules, 'error': None}
    
    @staticmethod
    def enable():
        """Enable UFW"""
        return UFWManager.run_command('sudo ufw --force enable')
    
    @staticmethod
    def disable():
        """Disable UFW"""
        return UFWManager.run_command('sudo ufw disable')
    
    @staticmethod
    def add_rule(action, target, comment=None):
        """Add a UFW rule"""
        # Validate input
        if action not in ['allow', 'deny']:
            return {'success': False, 'error': 'Invalid action'}
        
        # Basic validation for target
        if not re.match(r'^[a-zA-Z0-9\.\/:_-]+$', target):
            return {'success': False, 'error': 'Invalid target format'}
        
        command = f'sudo ufw {action} {target}'
        if comment:
            command += f' comment "{comment}"'
        
        return UFWManager.run_command(command)
    
    @staticmethod
    def delete_rule(rule_number):
        """Delete a UFW rule by number"""
        try:
            rule_num = int(rule_number)
            return UFWManager.run_command(f'sudo ufw --force delete {rule_num}')
        except ValueError:
            return {'success': False, 'error': 'Invalid rule number'}
    
    @staticmethod
    def reset():
        """Reset UFW to defaults"""
        return UFWManager.run_command('sudo ufw --force reset')
    
    @staticmethod
    def get_logs():
        """Get UFW logs"""
        result = UFWManager.run_command('sudo grep UFW /var/log/syslog | tail -50')
        if result['success']:
            return result['output'].split('\n')
        return []

def login_required(f):
    """Decorator to require login"""
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        
        # Check session timeout
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(minutes=CONFIG['SESSION_TIMEOUT']):
                session.clear()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
        
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/')
def index():
    """Redirect to dashboard or login"""
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['logged_in'] = True
            session['username'] = username
            session['last_activity'] = datetime.now().isoformat()
            flash('Successfully logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    flash('Successfully logged out!', 'success')
    return redirect(url_for('login'))

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
    """API endpoint to add a rule"""
    data = request.json
    action = data.get('action')
    target = data.get('target')
    comment = data.get('comment', '')
    
    if not action or not target:
        return jsonify({'success': False, 'error': 'Missing required fields'})
    
    result = UFWManager.add_rule(action, target, comment)
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
    
    print(f"Starting UFW Web Manager on {CONFIG['HOST']}:{CONFIG['PORT']}")
    print("Default credentials: admin / ufw-admin-2024")
    print("Please change the default password after first login!")
    
    app.run(
        host=CONFIG['HOST'],
        port=CONFIG['PORT'],
        debug=CONFIG['DEBUG']
    )
