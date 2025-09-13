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
    def run_command(command_list):
        """Execute UFW command safely by passing a list of arguments"""
        try:
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
        """Get UFW status and rules"""
        result = UFWManager.run_command(['sudo', 'ufw', 'status', 'verbose'])
        if not result['success']:
            return {'active': False, 'rules': [], 'numbered_rules': [], 'error': result['error']}
        
        output = result['output']
        active = 'Status: active' in output
        
        rules = []
        lines = output.split('\n')
        for line in lines:
            if '->' in line or 'ALLOW' in line or 'DENY' in line:
                rules.append(line.strip())
        
        # Also get numbered rules for deletion
        numbered_result = UFWManager.run_command(['sudo', 'ufw', 'status', 'numbered'])
        numbered_rules = []
        if numbered_result['success']:
            numbered_lines = numbered_result['output'].split('\n')
            for line in numbered_lines:
                # Look for lines that start with [ followed by a number
                line = line.strip()
                if line.startswith('[') and ']' in line:
                    # Extract rule number and rule text
                    match = re.match(r'\[\s*(\d+)\s*\]\s*(.*)', line)
                    if match:
                        rule_number = match.group(1)
                        rule_text = match.group(2).strip()
                        if rule_text:  # Only add non-empty rules
                            numbered_rules.append({
                                'number': rule_number,
                                'rule': rule_text
                            })
        
        return {
            'active': active, 
            'rules': rules, 
            'numbered_rules': numbered_rules,
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
    def add_rule(action, net_protocol, transport_protocol, port, source_ip='any', dest_ip='any', comment=None):
        """Add a comprehensive UFW rule with full from/to syntax"""
        # Validate input
        if action not in ['allow', 'deny']:
            return {'success': False, 'error': 'Invalid action'}
        
        if net_protocol not in ['any', 'ipv4', 'ipv6']:
            return {'success': False, 'error': 'Invalid network protocol. Must be any, ipv4, or ipv6'}
            
        if transport_protocol not in ['any', 'tcp', 'udp']:
            return {'success': False, 'error': 'Invalid transport protocol. Must be any, tcp, or udp'}
        
        # Validate port
        if not re.match(r'^[a-zA-Z0-9\:_-]+$', port):
            return {'success': False, 'error': 'Invalid port format'}
        
        # Build UFW command using from/to syntax
        command_parts = ['sudo', 'ufw', action]
        
        # Build UFW command using ALWAYS the full from/to syntax
        command_parts = ['sudo', 'ufw', action]
        
        # Handle source - always specify from
        if source_ip == 'any':
            if net_protocol == 'ipv6':
                source = '::/0'  # IPv6 equivalent of 0.0.0.0/0
            elif net_protocol == 'ipv4':
                source = '0.0.0.0/0'  # IPv4 any
            else:  # any protocol
                source = '0.0.0.0/0'  # Default to IPv4 any
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
            proto_comment = f" ({net_protocol.upper()}" + (f"/{transport_protocol.upper()}" if transport_protocol != 'any' else "") + ")"
            comment_text = f"{comment}{proto_comment}"
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
            if not status['numbered_rules']:
                return {'success': False, 'error': 'No rules to delete'}
            
            # Find the rule to confirm its existence
            rule_exists = any(r['number'] == str(rule_num) for r in status['numbered_rules'])
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
    """API endpoint to add a comprehensive rule"""
    data = request.json
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
    
    print(f"Starting UFW Web Manager on {CONFIG['HOST']}:{CONFIG['PORT']}")
    print("Default credentials: admin / ufw-admin-2024")
    print("Please change the default password after first login!")
    
    app.run(
        host=CONFIG['HOST'],
        port=CONFIG['PORT'],
        debug=CONFIG['DEBUG']
    )
