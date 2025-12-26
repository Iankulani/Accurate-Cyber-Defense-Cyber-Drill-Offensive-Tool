"""
ACCURATE CYBER DEFENSE - ULTIMATE TELEGRAM INTEGRATED TOOL
Author: Ian Carter Kulani
Version: 2.0.0 - Complete Integration
Description: Comprehensive cybersecurity tool with Telegram bot integration,
             network monitoring, traffic generation, SSH client, and advanced defense tools
"""

import os
import sys
import socket
import threading
import time
import json
import logging
from typing import Dict, List, Set, Tuple, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
from collections import deque
import queue
import subprocess
import requests
import random
import platform
import psutil
import getpass
import hashlib
import sqlite3
import ipaddress
import re
import shutil
import urllib.parse
import base64
import argparse
import secrets

# Telegram specific imports
import asyncio
from telegram import Update, Bot, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    CallbackQueryHandler,
    ContextTypes,
    ConversationHandler
)

# Core imports with fallbacks
try:
    import paramiko
    from paramiko import SSHClient, AutoAddPolicy, RSAKey, SSHException
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("⚠️ SSH features disabled (install: pip install paramiko)")

try:
    import scapy.all as scapy
    from scapy.all import IP, ICMP, TCP, UDP, ARP, Ether, send, sr
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Traffic generation disabled (install: pip install scapy)")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️ Advanced scans disabled (install: pip install python-nmap)")

# GUI imports
GUI_AVAILABLE = False
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext, Menu
    GUI_AVAILABLE = True
except ImportError:
    print("⚠️ GUI features disabled (install tkinter)")

# Configuration
CONFIG_FILE = "cyber_defense_config.json"
DATABASE_FILE = "network_security.db"
TELEGRAM_CONFIG_FILE = "telegram_config.json"
REPORT_DIR = "reports"
LOG_DIR = "logs"
BACKUP_DIR = "backups"

# Create directories
for directory in [REPORT_DIR, LOG_DIR, BACKUP_DIR]:
    os.makedirs(directory, exist_ok=True)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, f"cyber_defense_{datetime.now().strftime('%Y%m%d')}.log")),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("CyberDefense")

# ANSI Colors for Console
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# ==================== DATABASE MANAGER ====================

class DatabaseManager:
    """Unified database management"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize all database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Core tables
        tables = {
            "monitored_ips": """
                CREATE TABLE IF NOT EXISTS monitored_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    threat_level INTEGER DEFAULT 0,
                    last_scan TIMESTAMP
                )
            """,
            "threat_logs": """
                CREATE TABLE IF NOT EXISTS threat_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved BOOLEAN DEFAULT 0
                )
            """,
            "command_history": """
                CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command TEXT NOT NULL,
                    source TEXT DEFAULT 'local',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT 1
                )
            """,
            "scan_results": """
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    open_ports TEXT,
                    services TEXT,
                    os_info TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """,
            "traceroute_results": """
                CREATE TABLE IF NOT EXISTS traceroute_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    command TEXT NOT NULL,
                    output TEXT,
                    execution_time REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """,
            "telegram_users": """
                CREATE TABLE IF NOT EXISTS telegram_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER UNIQUE NOT NULL,
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    authorized BOOLEAN DEFAULT 0,
                    last_active TIMESTAMP,
                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """,
            "telegram_commands": """
                CREATE TABLE IF NOT EXISTS telegram_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    command TEXT NOT NULL,
                    arguments TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT 1
                )
            """,
            "ssh_sessions": """
                CREATE TABLE IF NOT EXISTS ssh_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT NOT NULL,
                    username TEXT NOT NULL,
                    port INTEGER DEFAULT 22,
                    auth_type TEXT DEFAULT 'password',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    successful BOOLEAN DEFAULT 0
                )
            """,
            "ssh_commands": """
                CREATE TABLE IF NOT EXISTS ssh_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    command TEXT NOT NULL,
                    output TEXT,
                    execution_time REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """,
            "traffic_logs": """
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    traffic_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    packets_sent INTEGER,
                    duration REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
        }
        
        for table_name, table_sql in tables.items():
            try:
                cursor.execute(table_sql)
                logger.info(f"Table {table_name} initialized")
            except Exception as e:
                logger.error(f"Failed to create table {table_name}: {e}")
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True):
        """Log command execution"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)',
            (command[:500], source, success)
        )
        conn.commit()
        conn.close()
    
    def log_telegram_command(self, user_id: int, command: str, arguments: str = "", success: bool = True):
        """Log Telegram command"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO telegram_commands (user_id, command, arguments, success) VALUES (?, ?, ?, ?)',
            (user_id, command, arguments, success)
        )
        conn.commit()
        conn.close()
    
    def register_telegram_user(self, user_id: int, username: str = "", 
                              first_name: str = "", last_name: str = ""):
        """Register or update Telegram user"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            '''INSERT OR REPLACE INTO telegram_users 
               (user_id, username, first_name, last_name, last_active) 
               VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (user_id, username, first_name, last_name)
        )
        
        conn.commit()
        conn.close()
    
    def authorize_user(self, user_id: int, authorized: bool = True):
        """Authorize/unauthorize Telegram user"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE telegram_users SET authorized = ? WHERE user_id = ?',
            (authorized, user_id)
        )
        conn.commit()
        conn.close()
    
    def is_user_authorized(self, user_id: int) -> bool:
        """Check if user is authorized"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT authorized FROM telegram_users WHERE user_id = ?',
            (user_id,)
        )
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else False
    
    def get_authorized_users(self) -> List[Tuple]:
        """Get all authorized users"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT user_id, username, first_name, last_name FROM telegram_users WHERE authorized = 1'
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_recent_telegram_commands(self, limit: int = 20) -> List[Tuple]:
        """Get recent Telegram commands"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT tc.command, tc.arguments, tc.timestamp, tu.username 
            FROM telegram_commands tc
            LEFT JOIN telegram_users tu ON tc.user_id = tu.user_id
            ORDER BY tc.timestamp DESC LIMIT ?
        ''', (limit,))
        results = cursor.fetchall()
        conn.close()
        return results
    
    def log_threat(self, ip_address: str, threat_type: str, severity: str, description: str = ""):
        """Log threat detection"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO threat_logs (ip_address, threat_type, severity, description) VALUES (?, ?, ?, ?)',
            (ip_address, threat_type, severity, description)
        )
        conn.commit()
        conn.close()
    
    def get_recent_threats(self, limit: int = 20) -> List[Tuple]:
        """Get recent threats"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT ip_address, threat_type, severity, timestamp FROM threat_logs ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results

# ==================== TRACEROUTE TOOL ====================

class TracerouteTool:
    """Enhanced traceroute tool"""
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if name.endswith('.'):
            name = name[:-1]
        HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
        return bool(HOSTNAME_RE.match(name))
    
    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        system = platform.system()
        
        if system == 'Windows':
            return ['tracert', '-d', target]
        
        if shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '1', '-w', '2', target]
        if shutil.which('tracepath'):
            return ['tracepath', target]
        if shutil.which('ping'):
            return ['ping', '-c', '4', target]
        
        raise EnvironmentError('No traceroute utilities found')
    
    @staticmethod
    def stream_subprocess(cmd: List[str]) -> Tuple[int, str]:
        """Run subprocess and capture output"""
        output_lines = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            
            if proc.stdout:
                for line in proc.stdout:
                    cleaned_line = line.rstrip()
                    output_lines.append(cleaned_line)
                    print(cleaned_line)
            
            proc.wait()
            return proc.returncode, '\n'.join(output_lines)
        except KeyboardInterrupt:
            print('\n[+] User cancelled traceroute...')
            try:
                proc.terminate()
            except Exception:
                pass
            return -1, '\n'.join(output_lines)
        except Exception as e:
            error_msg = f'[!] Error: {e}'
            print(error_msg)
            output_lines.append(error_msg)
            return -2, '\n'.join(output_lines)
    
    def interactive_traceroute(self, target: str = None) -> str:
        """Run interactive traceroute with validation"""
        if not target:
            target = input("Enter target IP/hostname: ").strip()
            if not target:
                return "Traceroute cancelled."
        
        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"
        
        try:
            cmd = self.choose_traceroute_cmd(target)
        except EnvironmentError as e:
            return f"❌ Traceroute error: {e}"
        
        print(f'Running: {" ".join(cmd)}\n')
        
        start_time = time.time()
        returncode, output = self.stream_subprocess(cmd)
        execution_time = time.time() - start_time
        
        # Save to database
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO traceroute_results (target, command, output, execution_time) VALUES (?, ?, ?, ?)',
            (target, ' '.join(cmd), output, execution_time)
        )
        conn.commit()
        conn.close()
        
        result = f"🛣️ Traceroute to {target}\n\n"
        result += f"Command: {' '.join(cmd)}\n"
        result += f"Execution time: {execution_time:.2f}s\n"
        result += f"Return code: {returncode}\n\n"
        
        if len(output) > 3000:
            result += f"{output[-3000:]}"
        else:
            result += f"{output}"
        
        return result

# ==================== NETWORK SCANNER ====================

class NetworkScanner:
    """Network scanning capabilities"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.traceroute_tool = TracerouteTool()
        
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
    
    def ping_ip(self, ip: str, count: int = 4) -> str:
        """Ping IP address"""
        try:
            if os.name == 'nt':
                cmd = ['ping', '-n', str(count), ip]
            else:
                cmd = ['ping', '-c', str(count), ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Ping timeout for {ip}"
        except Exception as e:
            return f"Ping error: {str(e)}"
    
    def traceroute(self, target: str) -> str:
        """Perform traceroute"""
        return self.traceroute_tool.interactive_traceroute(target)
    
    def port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform port scan"""
        if self.nm:
            try:
                self.nm.scan(ip, ports, arguments='-T4')
                open_ports = []
                
                if ip in self.nm.all_hosts():
                    for proto in self.nm[ip].all_protocols():
                        lport = self.nm[ip][proto].keys()
                        for port in lport:
                            if self.nm[ip][proto][port]['state'] == 'open':
                                open_ports.append({
                                    'port': port,
                                    'state': self.nm[ip][proto][port]['state'],
                                    'service': self.nm[ip][proto][port].get('name', 'unknown')
                                })
                
                # Save to database
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                open_ports_json = json.dumps([p['port'] for p in open_ports])
                services_json = json.dumps([p.get('service', '') for p in open_ports])
                cursor.execute(
                    'INSERT INTO scan_results (ip_address, scan_type, open_ports, services) VALUES (?, ?, ?, ?)',
                    (ip, 'nmap', open_ports_json, services_json)
                )
                conn.commit()
                conn.close()
                
                return {
                    'success': True,
                    'target': ip,
                    'open_ports': open_ports,
                    'scan_time': datetime.now().isoformat()
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': 'Nmap not available'}
    
    def get_ip_location(self, ip: str) -> str:
        """Get IP location using ip-api.com"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return json.dumps({
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }, indent=2)
                else:
                    return f"Location error: {data.get('message', 'Unknown error')}"
            else:
                return f"Location error: HTTP {response.status_code}"
        except Exception as e:
            return f"Location error: {str(e)}"
    
    def analyze_ip(self, ip: str) -> str:
        """Comprehensive IP analysis"""
        result = f"🔍 Analysis for {ip}\n\n"
        
        # Get location
        location = self.get_ip_location(ip)
        try:
            loc_data = json.loads(location)
            result += f"📍 Location: {loc_data.get('city', 'N/A')}, {loc_data.get('country', 'N/A')}\n"
            result += f"🏢 ISP: {loc_data.get('isp', 'N/A')}\n\n"
        except:
            result += f"📍 Location info: {location}\n\n"
        
        # Check for threats in database
        threats = self.db.get_recent_threats(10)
        ip_threats = [t for t in threats if t[0] == ip]
        if ip_threats:
            result += f"🚨 Threats Found: {len(ip_threats)}\n"
            for threat in ip_threats[:5]:
                result += f"• {threat[1]}: {threat[2]}\n"
        else:
            result += "✅ No recent threats detected\n"
        
        return result

# ==================== SSH CLIENT MANAGER ====================

class SSHClientManager:
    """SSH connection manager"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.connections = {}
        self.current_session_id = None
    
    def connect_password(self, host: str, username: str, password: str, port: int = 22) -> Tuple[bool, str]:
        """Connect via SSH using password authentication"""
        if not SSH_AVAILABLE:
            return False, "SSH not available"
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            start_time = time.time()
            client.connect(hostname=host, username=username, password=password, port=port, timeout=10)
            connection_time = time.time() - start_time
            
            session_id = hash(f"{host}:{username}:{time.time()}")
            self.connections[session_id] = {
                'client': client,
                'host': host,
                'username': username,
                'port': port,
                'auth_type': 'password',
                'connected_at': datetime.now()
            }
            
            self.current_session_id = session_id
            self.db.log_command(f"ssh_connect {host}:{port}", 'local', True)
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO ssh_sessions (host, username, port, auth_type, successful) VALUES (?, ?, ?, ?, ?)',
                (host, username, port, 'password', True)
            )
            conn.commit()
            conn.close()
            
            return True, f"✅ Connected to {host} as {username} in {connection_time:.2f}s"
            
        except paramiko.AuthenticationException:
            return False, "❌ Authentication failed"
        except paramiko.SSHException as e:
            return False, f"❌ SSH error: {str(e)}"
        except Exception as e:
            return False, f"❌ Connection error: {str(e)}"
    
    def connect_key(self, host: str, username: str, key_path: str, port: int = 22, 
                   key_password: str = None) -> Tuple[bool, str]:
        """Connect via SSH using key authentication"""
        if not SSH_AVAILABLE:
            return False, "SSH not available"
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            key = paramiko.RSAKey.from_private_key_file(key_path, password=key_password)
            
            start_time = time.time()
            client.connect(hostname=host, username=username, pkey=key, port=port, timeout=10)
            connection_time = time.time() - start_time
            
            session_id = hash(f"{host}:{username}:{time.time()}")
            self.connections[session_id] = {
                'client': client,
                'host': host,
                'username': username,
                'port': port,
                'auth_type': 'key',
                'connected_at': datetime.now()
            }
            
            self.current_session_id = session_id
            self.db.log_command(f"ssh_key_connect {host}:{port}", 'local', True)
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO ssh_sessions (host, username, port, auth_type, successful) VALUES (?, ?, ?, ?, ?)',
                (host, username, port, 'key', True)
            )
            conn.commit()
            conn.close()
            
            return True, f"✅ Connected to {host} as {username} using key in {connection_time:.2f}s"
            
        except paramiko.AuthenticationException:
            return False, "❌ Key authentication failed"
        except Exception as e:
            return False, f"❌ Connection error: {str(e)}"
    
    def execute_command(self, command: str, session_id: int = None) -> Tuple[bool, str]:
        """Execute command on SSH server"""
        if not session_id:
            session_id = self.current_session_id
        
        if session_id not in self.connections:
            return False, "❌ No active SSH session"
        
        try:
            client = self.connections[session_id]['client']
            start_time = time.time()
            
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            execution_time = time.time() - start_time
            
            result = output if output else error
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO ssh_commands (session_id, command, output, execution_time) VALUES (?, ?, ?, ?)',
                (session_id, command, result[:1000], execution_time)
            )
            conn.commit()
            conn.close()
            
            return True, f"⏱️ Execution time: {execution_time:.2f}s\n\n{result}"
            
        except Exception as e:
            return False, f"❌ Command execution error: {str(e)}"
    
    def disconnect(self, session_id: int = None) -> Tuple[bool, str]:
        """Disconnect SSH session"""
        if not session_id:
            session_id = self.current_session_id
        
        if session_id in self.connections:
            try:
                host = self.connections[session_id]['host']
                self.connections[session_id]['client'].close()
                del self.connections[session_id]
                
                if self.current_session_id == session_id:
                    self.current_session_id = None
                
                return True, f"✅ Disconnected from {host}"
            except Exception as e:
                return False, f"❌ Disconnect error: {str(e)}"
        
        return False, "❌ No active session to disconnect"
    
    def get_active_sessions(self) -> List[Dict]:
        """Get list of active SSH sessions"""
        sessions = []
        for session_id, info in self.connections.items():
            sessions.append({
                'id': session_id,
                'host': info['host'],
                'username': info['username'],
                'auth_type': info['auth_type'],
                'connected_at': info['connected_at']
            })
        return sessions

# ==================== TRAFFIC GENERATOR ====================

class TrafficGenerator:
    """Network traffic generation capabilities"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.running = False
        self.threads = []
    
    def generate_tcp_traffic(self, target_ip: str, port: int, packet_count: int, delay: float) -> str:
        """Generate TCP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for TCP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                packet = IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=port)
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO traffic_logs (traffic_type, target, packets_sent, duration) VALUES (?, ?, ?, ?)',
                ('TCP Flood', f"{target_ip}:{port}", packets_sent, duration)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} TCP packets to {target_ip}:{port} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ TCP traffic error: {str(e)}"
    
    def generate_udp_traffic(self, target_ip: str, port: int, packet_count: int, delay: float) -> str:
        """Generate UDP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for UDP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                payload = random._urandom(random.randint(64, 512))
                packet = IP(src=src_ip, dst=target_ip)/UDP(sport=random.randint(1024, 65535), dport=port)/payload
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO traffic_logs (traffic_type, target, packets_sent, duration) VALUES (?, ?, ?, ?)',
                ('UDP Flood', f"{target_ip}:{port}", packets_sent, duration)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} UDP packets to {target_ip}:{port} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ UDP traffic error: {str(e)}"
    
    def generate_icmp_traffic(self, target_ip: str, packet_count: int, delay: float) -> str:
        """Generate ICMP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for ICMP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                packet = IP(dst=target_ip)/ICMP()
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO traffic_logs (traffic_type, target, packets_sent, duration) VALUES (?, ?, ?, ?)',
                ('ICMP Flood', target_ip, packets_sent, duration)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} ICMP packets to {target_ip} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ ICMP traffic error: {str(e)}"
    
    def start_traffic(self, traffic_type: str, target: str, port: int = None, 
                     packet_count: int = 100, delay: float = 0.1) -> str:
        """Start traffic generation"""
        self.running = True
        
        if ":" in target:
            target_ip, port_str = target.split(":", 1)
            port = int(port_str)
        else:
            target_ip = target
        
        if traffic_type.lower() == "tcp" and port:
            def traffic_thread():
                result = self.generate_tcp_traffic(target_ip, port, packet_count, delay)
                print(result)
            
            thread = threading.Thread(target=traffic_thread, daemon=True)
            self.threads.append(thread)
            thread.start()
            return f"🚀 Started TCP traffic to {target_ip}:{port}"
        
        elif traffic_type.lower() == "udp" and port:
            def traffic_thread():
                result = self.generate_udp_traffic(target_ip, port, packet_count, delay)
                print(result)
            
            thread = threading.Thread(target=traffic_thread, daemon=True)
            self.threads.append(thread)
            thread.start()
            return f"🚀 Started UDP traffic to {target_ip}:{port}"
        
        elif traffic_type.lower() == "icmp":
            def traffic_thread():
                result = self.generate_icmp_traffic(target_ip, packet_count, delay)
                print(result)
            
            thread = threading.Thread(target=traffic_thread, daemon=True)
            self.threads.append(thread)
            thread.start()
            return f"🚀 Started ICMP traffic to {target_ip}"
        
        return f"❌ Invalid traffic type or missing port: {traffic_type}"
    
    def stop_traffic(self):
        """Stop all traffic generation"""
        self.running = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        self.threads = []
        return "🛑 All traffic generation stopped"

# ==================== TELEGRAM BOT HANDLER ====================

class TelegramBotHandler:
    """Telegram bot handler with async support"""
    
    def __init__(self, token: str, db_manager: DatabaseManager, scanner: NetworkScanner,
                 ssh_manager: SSHClientManager, traffic_gen: TrafficGenerator):
        self.token = token
        self.db = db_manager
        self.scanner = scanner
        self.ssh_manager = ssh_manager
        self.traffic_gen = traffic_gen
        self.application = None
        self.bot = None
        self.chat_ids = set()
        
        # Load saved chat IDs
        self.load_chat_ids()
    
    def load_chat_ids(self):
        """Load chat IDs from database"""
        authorized_users = self.db.get_authorized_users()
        for user in authorized_users:
            self.chat_ids.add(user[0])
    
    async def start(self):
        """Start the Telegram bot"""
        if not self.token:
            logger.error("Telegram token not provided")
            return
        
        try:
            self.application = Application.builder().token(self.token).build()
            self.bot = self.application.bot
            
            # Add handlers
            self.application.add_handler(CommandHandler("start", self.start_command))
            self.application.add_handler(CommandHandler("help", self.help_command))
            self.application.add_handler(CommandHandler("ping", self.ping_command))
            self.application.add_handler(CommandHandler("traceroute", self.traceroute_command))
            self.application.add_handler(CommandHandler("scan", self.scan_command))
            self.application.add_handler(CommandHandler("analyze", self.analyze_command))
            self.application.add_handler(CommandHandler("location", self.location_command))
            self.application.add_handler(CommandHandler("ssh_connect", self.ssh_connect_command))
            self.application.add_handler(CommandHandler("ssh_command", self.ssh_command_command))
            self.application.add_handler(CommandHandler("ssh_disconnect", self.ssh_disconnect_command))
            self.application.add_handler(CommandHandler("traffic", self.traffic_command))
            self.application.add_handler(CommandHandler("stop_traffic", self.stop_traffic_command))
            self.application.add_handler(CommandHandler("status", self.status_command))
            self.application.add_handler(CommandHandler("history", self.history_command))
            self.application.add_handler(CommandHandler("threats", self.threats_command))
            self.application.add_handler(CommandHandler("report", self.report_command))
            
            # Start the bot
            await self.application.initialize()
            await self.application.start()
            await self.application.updater.start_polling()
            
            logger.info("Telegram bot started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start Telegram bot: {e}")
    
    async def stop(self):
        """Stop the Telegram bot"""
        if self.application:
            await self.application.stop()
            await self.application.shutdown()
    
    async def send_message(self, chat_id: int, text: str, parse_mode: str = None):
        """Send message to Telegram chat"""
        try:
            if len(text) > 4096:
                # Split long messages
                messages = [text[i:i+4096] for i in range(0, len(text), 4096)]
                for msg in messages:
                    await self.bot.send_message(chat_id=chat_id, text=msg, parse_mode=parse_mode)
                    await asyncio.sleep(0.5)
            else:
                await self.bot.send_message(chat_id=chat_id, text=text, parse_mode=parse_mode)
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        user = update.effective_user
        chat_id = update.effective_chat.id
        
        # Register user
        self.db.register_telegram_user(
            user.id, 
            user.username, 
            user.first_name, 
            user.last_name
        )
        self.db.authorize_user(user.id, True)
        self.chat_ids.add(chat_id)
        
        welcome_msg = f"""
🚀 *Welcome to Accurate Cyber Defense, {user.first_name}!* 🚀

Your advanced cybersecurity assistant is now active.

🔍 *Network Diagnostics:*
/ping [IP] - Ping IP address
/traceroute [IP] - Traceroute
/scan [IP] - Port scan
/location [IP] - Get IP location
/analyze [IP] - Analyze IP threats

🔐 *SSH Operations:*
/ssh_connect host user pass - SSH connect
/ssh_command [cmd] - Execute SSH command
/ssh_disconnect - Disconnect SSH

🌐 *Traffic Generation:*
/traffic [tcp|udp|icmp] target - Generate traffic
/stop_traffic - Stop all traffic

📊 *Monitoring & Reports:*
/status - System status
/history - Command history
/threats - Recent threats
/report - Generate security report

❓ /help - Detailed command reference

⚠️ *Note:* Use responsibly and only on authorized systems.
"""
        
        await self.send_message(chat_id, welcome_msg, parse_mode='Markdown')
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        help_msg = """
*🔒 Complete Command Reference*

*🌐 Network Diagnostics:*
`/ping 8.8.8.8` - Ping IP address
`/traceroute google.com` - Traceroute
`/scan 192.168.1.1` - Port scan
`/location 1.1.1.1` - Get IP location
`/analyze 192.168.1.1` - Analyze IP

*🔐 SSH Operations:*
`/ssh_connect 192.168.1.100 admin password123` - SSH connect
`/ssh_command ls -la` - Execute SSH command
`/ssh_disconnect` - Disconnect SSH

*🌐 Traffic Generation:*
`/traffic tcp 192.168.1.1:80` - TCP traffic
`/traffic udp 10.0.0.1:53` - UDP traffic
`/traffic icmp 8.8.8.8` - ICMP traffic
`/stop_traffic` - Stop all traffic

*📊 Monitoring:*
`/status` - System status
`/history` - Command history
`/threats` - Recent threats
`/report` - Generate report
"""
        
        await self.send_message(update.effective_chat.id, help_msg, parse_mode='Markdown')
    
    async def ping_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /ping command"""
        chat_id = update.effective_chat.id
        
        if not context.args:
            await self.send_message(chat_id, "❌ Usage: `/ping [IP address]`", parse_mode='Markdown')
            return
        
        ip = context.args[0]
        await self.send_message(chat_id, f"🏓 Pinging {ip}...")
        
        result = self.scanner.ping_ip(ip)
        self.db.log_telegram_command(update.effective_user.id, "ping", ip, True)
        
        response = f"*Ping Results for {ip}*\n\n```\n{result[-500:]}\n```"
        await self.send_message(chat_id, response, parse_mode='Markdown')
    
    async def traceroute_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /traceroute command"""
        chat_id = update.effective_chat.id
        
        if not context.args:
            await self.send_message(chat_id, "❌ Usage: `/traceroute [IP/hostname]`", parse_mode='Markdown')
            return
        
        target = context.args[0]
        await self.send_message(chat_id, f"🛣️ Tracing route to {target}...")
        
        result = self.scanner.traceroute(target)
        self.db.log_telegram_command(update.effective_user.id, "traceroute", target, True)
        
        await self.send_message(chat_id, f"```\n{result}\n```", parse_mode='Markdown')
    
    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /scan command"""
        chat_id = update.effective_chat.id
        
        if not context.args:
            await self.send_message(chat_id, "❌ Usage: `/scan [IP address]`", parse_mode='Markdown')
            return
        
        ip = context.args[0]
        await self.send_message(chat_id, f"🔍 Scanning {ip}...")
        
        result = self.scanner.port_scan(ip)
        self.db.log_telegram_command(update.effective_user.id, "scan", ip, True)
        
        if result['success']:
            open_ports = result.get('open_ports', [])
            response = f"*Scan Results: {ip}*\n\n"
            response += f"Open Ports: {len(open_ports)}\n\n"
            
            if open_ports:
                for port in open_ports[:10]:
                    response += f"• Port {port['port']}: {port['service']}\n"
                if len(open_ports) > 10:
                    response += f"\n... and {len(open_ports)-10} more"
            else:
                response += "🔒 No open ports found"
        else:
            response = f"❌ Scan error: {result.get('error', 'Unknown')}"
        
        await self.send_message(chat_id, response, parse_mode='Markdown')
    
    async def analyze_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /analyze command"""
        chat_id = update.effective_chat.id
        
        if not context.args:
            await self.send_message(chat_id, "❌ Usage: `/analyze [IP address]`", parse_mode='Markdown')
            return
        
        ip = context.args[0]
        await self.send_message(chat_id, f"🔍 Analyzing {ip}...")
        
        result = self.scanner.analyze_ip(ip)
        self.db.log_telegram_command(update.effective_user.id, "analyze", ip, True)
        
        await self.send_message(chat_id, result)
    
    async def location_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /location command"""
        chat_id = update.effective_chat.id
        
        if not context.args:
            await self.send_message(chat_id, "❌ Usage: `/location [IP address]`", parse_mode='Markdown')
            return
        
        ip = context.args[0]
        await self.send_message(chat_id, f"🌍 Getting location for {ip}...")
        
        result = self.scanner.get_ip_location(ip)
        self.db.log_telegram_command(update.effective_user.id, "location", ip, True)
        
        response = f"*Location Information for {ip}*\n\n```\n{result}\n```"
        await self.send_message(chat_id, response, parse_mode='Markdown')
    
    async def ssh_connect_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /ssh_connect command"""
        chat_id = update.effective_chat.id
        
        if len(context.args) < 3:
            await self.send_message(chat_id, "❌ Usage: `/ssh_connect [host] [username] [password] [port]`", parse_mode='Markdown')
            return
        
        host = context.args[0]
        username = context.args[1]
        password = context.args[2]
        port = int(context.args[3]) if len(context.args) > 3 else 22
        
        await self.send_message(chat_id, f"🔐 Connecting to {host}...")
        
        success, message = self.ssh_manager.connect_password(host, username, password, port)
        self.db.log_telegram_command(update.effective_user.id, "ssh_connect", f"{host}:{port}", success)
        
        await self.send_message(chat_id, message)
    
    async def ssh_command_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /ssh_command command"""
        chat_id = update.effective_chat.id
        
        if not context.args:
            await self.send_message(chat_id, "❌ Usage: `/ssh_command [command]`", parse_mode='Markdown')
            return
        
        command = " ".join(context.args)
        await self.send_message(chat_id, f"💻 Executing: `{command}`")
        
        success, output = self.ssh_manager.execute_command(command)
        self.db.log_telegram_command(update.effective_user.id, "ssh_command", command[:100], success)
        
        response = f"*Command Output:*\n\n```\n{output[:1000]}\n```"
        await self.send_message(chat_id, response, parse_mode='Markdown')
    
    async def ssh_disconnect_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /ssh_disconnect command"""
        chat_id = update.effective_chat.id
        
        success, message = self.ssh_manager.disconnect()
        self.db.log_telegram_command(update.effective_user.id, "ssh_disconnect", "", success)
        
        await self.send_message(chat_id, message)
    
    async def traffic_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /traffic command"""
        chat_id = update.effective_chat.id
        
        if len(context.args) < 2:
            await self.send_message(chat_id, "❌ Usage: `/traffic [tcp|udp|icmp] [target]`", parse_mode='Markdown')
            return
        
        traffic_type = context.args[0].lower()
        target = context.args[1]
        
        await self.send_message(chat_id, f"🌐 Starting {traffic_type.upper()} traffic to {target}...")
        
        result = self.traffic_gen.start_traffic(traffic_type, target)
        self.db.log_telegram_command(update.effective_user.id, "traffic", f"{traffic_type} {target}", True)
        
        await self.send_message(chat_id, result)
    
    async def stop_traffic_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /stop_traffic command"""
        chat_id = update.effective_chat.id
        
        result = self.traffic_gen.stop_traffic()
        self.db.log_telegram_command(update.effective_user.id, "stop_traffic", "", True)
        
        await self.send_message(chat_id, result)
    
    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command"""
        chat_id = update.effective_chat.id
        
        # System information
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        
        # Network information
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except:
            local_ip = "Unknown"
        
        # Bot status
        ssh_sessions = len(self.ssh_manager.get_active_sessions())
        
        status_msg = f"""
*📊 System Status*

*💻 System Information:*
• Hostname: `{hostname}`
• Local IP: `{local_ip}`
• OS: {platform.system()} {platform.release()}
• CPU Usage: {cpu}%
• Memory Usage: {mem.percent}%

*🤖 Bot Status:*
• Active SSH Sessions: {ssh_sessions}
• Traffic Generation: {'Running' if self.traffic_gen.running else 'Stopped'}
• Telegram Users: {len(self.chat_ids)}

*⚡ Quick Commands:*
• `/ping 8.8.8.8` - Test connectivity
• `/scan localhost` - Scan local machine
• `/status` - Check this status
"""
        
        self.db.log_telegram_command(update.effective_user.id, "status", "", True)
        await self.send_message(chat_id, status_msg, parse_mode='Markdown')
    
    async def history_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /history command"""
        chat_id = update.effective_chat.id
        
        history = self.db.get_recent_telegram_commands(10)
        
        if not history:
            await self.send_message(chat_id, "📝 No commands recorded yet")
            return
        
        response = "*📜 Recent Telegram Commands*\n\n"
        for cmd, args, timestamp, username in history:
            status = "✅"  # All logged commands are successful
            response += f"{status} `{cmd}`"
            if args:
                response += f" `{args}`"
            response += f"\n   👤 {username or 'Unknown'} | {timestamp}\n\n"
        
        self.db.log_telegram_command(update.effective_user.id, "history", "", True)
        await self.send_message(chat_id, response, parse_mode='Markdown')
    
    async def threats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /threats command"""
        chat_id = update.effective_chat.id
        
        threats = self.db.get_recent_threats(10)
        
        if not threats:
            await self.send_message(chat_id, "✅ No recent threats detected")
            return
        
        response = "*🚨 Recent Threats*\n\n"
        for ip, ttype, severity, timestamp in threats:
            response += f"• `{ip}`\n"
            response += f"  Type: {ttype} | Severity: {severity}\n"
            response += f"  Time: {timestamp}\n\n"
        
        self.db.log_telegram_command(update.effective_user.id, "threats", "", True)
        await self.send_message(chat_id, response, parse_mode='Markdown')
    
    async def report_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /report command"""
        chat_id = update.effective_chat.id
        
        # Collect data
        threats = self.db.get_recent_threats(50)
        telegram_cmds = self.db.get_recent_telegram_commands(100)
        
        # Generate report
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_threats': len(threats),
            'high_severity': len([t for t in threats if t[2] == 'high']),
            'medium_severity': len([t for t in threats if t[2] == 'medium']),
            'low_severity': len([t for t in threats if t[2] == 'low']),
            'telegram_commands': len(telegram_cmds),
            'active_ssh_sessions': len(self.ssh_manager.get_active_sessions()),
            'telegram_users': len(self.chat_ids)
        }
        
        # Save report
        filename = f"telegram_report_{int(time.time())}.json"
        filepath = os.path.join(REPORT_DIR, filename)
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Send summary
        response = "*📊 Security Report*\n\n"
        response += f"• Total Threats: {report['total_threats']}\n"
        response += f"• High Severity: {report['high_severity']}\n"
        response += f"• Medium Severity: {report['medium_severity']}\n"
        response += f"• Low Severity: {report['low_severity']}\n"
        response += f"• Telegram Commands: {report['telegram_commands']}\n"
        response += f"• Active SSH Sessions: {report['active_ssh_sessions']}\n"
        response += f"• Telegram Users: {report['telegram_users']}\n\n"
        response += f"✅ Report saved as `{filename}`"
        
        self.db.log_telegram_command(update.effective_user.id, "report", "", True)
        await self.send_message(chat_id, response, parse_mode='Markdown')
    
    async def broadcast_message(self, message: str):
        """Broadcast message to all authorized users"""
        for chat_id in self.chat_ids:
            try:
                await self.send_message(chat_id, message)
            except Exception as e:
                logger.error(f"Failed to send broadcast to {chat_id}: {e}")

# ==================== MAIN APPLICATION ====================

class CyberDefenseTool:
    """Main cybersecurity tool with Telegram integration"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.scanner = NetworkScanner(self.db)
        self.ssh_manager = SSHClientManager(self.db)
        self.traffic_gen = TrafficGenerator(self.db)
        self.telegram_bot = None
        
        # Configuration
        self.config = self.load_config()
        self.telegram_token = self.config.get('telegram_token', '')
        
        # State
        self.running = False
        self.telegram_thread = None
    
    def load_config(self) -> Dict:
        """Load configuration from file"""
        config = {
            'telegram_token': '',
            'monitored_ips': []
        }
        
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    loaded_config = json.load(f)
                    config.update(loaded_config)
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
        
        return config
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def setup_telegram(self):
        """Setup Telegram bot"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}🔧 Telegram Bot Setup{Colors.END}")
        print("=" * 50)
        print("\nTo use Telegram commands:")
        print("1. Create a bot with @BotFather on Telegram")
        print("2. Get your bot token")
        print("3. Start chat with your bot and send /start")
        print("\nExample token: 1234567890:ABCdefGhIJKlmNoPQRsTUVwxyZ")
        
        if self.telegram_token:
            print(f"\nCurrent token: {self.telegram_token[:10]}...")
            change = input("Change token? (y/N): ").lower()
            if change != 'y':
                return
        
        token = input("\nEnter Telegram bot token (or press Enter to skip): ").strip()
        if token:
            self.telegram_token = token
            self.config['telegram_token'] = token
            self.save_config()
            print("✅ Telegram configured!")
            
            # Initialize bot
            self.telegram_bot = TelegramBotHandler(
                token, self.db, self.scanner, self.ssh_manager, self.traffic_gen
            )
        else:
            print("⚠️ Telegram features disabled")
    
    def start_telegram_bot(self):
        """Start Telegram bot in a separate thread"""
        if not self.telegram_bot or not self.telegram_token:
            logger.warning("Telegram bot not configured")
            return
        
        async def run_bot():
            await self.telegram_bot.start()
        
        def run_in_thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_bot())
                loop.run_forever()
            except KeyboardInterrupt:
                pass
            finally:
                loop.close()
        
        self.telegram_thread = threading.Thread(target=run_in_thread, daemon=True)
        self.telegram_thread.start()
        logger.info("Telegram bot thread started")
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║         🛡️  ACCURATE CYBER DEFENSE - TELEGRAM EDITION 🛡️         ║
    ║                                                                  ║
    ║      Network Monitoring • SSH Client • Traffic Generation        ║
    ║         Security Analysis • Threat Detection • Reporting         ║
    ║                                                                  ║
    ║              Telegram Bot: {'✅ ACTIVE' if self.telegram_token else '❌ DISABLED'}                          ║
    ║              Database: Ready                                     ║
    ║              SSH Client: {'✅ READY' if SSH_AVAILABLE else '❌ DISABLED'}                                ║
    ║              Traffic Generator: {'✅ READY' if SCAPY_AVAILABLE else '❌ DISABLED'}                         ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
        print(banner)
    
    def console_interface(self):
        """Console interface for the tool"""
        self.print_banner()
        
        if not self.telegram_token:
            self.setup_telegram()
        
        if self.telegram_token:
            print(f"\n{Colors.GREEN}✅ Telegram bot configured!{Colors.END}")
            print(f"📱 Send /start to your bot on Telegram")
            self.start_telegram_bot()
        
        print(f"\n{Colors.YELLOW}💻 Local Console Commands{Colors.END}")
        print("🎛️  Type 'gui' to open GUI tools")
        print("📋 Type 'help' for command list\n")
        
        while self.running:
            try:
                command = input(f"{Colors.CYAN}cyberdefense>{Colors.END} ").strip()
                if not command:
                    continue
                
                self.db.log_command(command, 'local', True)
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                if cmd == 'exit':
                    print("👋 Exiting...")
                    self.traffic_gen.stop_traffic()
                    for session_id in list(self.ssh_manager.connections.keys()):
                        self.ssh_manager.disconnect(session_id)
                    break
                
                elif cmd == 'help':
                    self.show_help()
                
                elif cmd == 'gui':
                    if GUI_AVAILABLE:
                        self.gui_interface()
                    else:
                        print("❌ GUI not available. Install tkinter.")
                
                elif cmd == 'ping' and args:
                    ip = args[0]
                    print(f"🏓 Pinging {ip}...")
                    result = self.scanner.ping_ip(ip)
                    print(result)
                
                elif cmd in ['tracert', 'traceroute'] and args:
                    target = args[0]
                    print(f"🛣️ Traceroute to {target}...")
                    result = self.scanner.traceroute(target)
                    print(result)
                
                elif cmd == 'scan' and args:
                    ip = args[0]
                    ports = args[1] if len(args) > 1 else "1-1000"
                    print(f"🔍 Scanning {ip} ports {ports}...")
                    result = self.scanner.port_scan(ip, ports)
                    if result['success']:
                        print(f"\n📊 Scan Results for {ip}:")
                        open_ports = result.get('open_ports', [])
                        print(f"Open Ports: {len(open_ports)}\n")
                        for p in open_ports:
                            print(f"  Port {p['port']}: {p['service']}")
                    else:
                        print(f"❌ Error: {result.get('error', 'Unknown')}")
                
                elif cmd == 'analyze' and args:
                    ip = args[0]
                    print(f"\n🔍 Analyzing {ip}...")
                    result = self.scanner.analyze_ip(ip)
                    print(result)
                
                elif cmd == 'location' and args:
                    ip = args[0]
                    print(f"🌍 Getting location for {ip}...")
                    result = self.scanner.get_ip_location(ip)
                    print(result)
                
                elif cmd == 'ssh_connect' and len(args) >= 3:
                    host = args[0]
                    username = args[1]
                    password = args[2]
                    port = int(args[3]) if len(args) > 3 else 22
                    
                    success, message = self.ssh_manager.connect_password(host, username, password, port)
                    print(message)
                
                elif cmd == 'ssh_command' and args:
                    ssh_cmd = " ".join(args)
                    success, output = self.ssh_manager.execute_command(ssh_cmd)
                    print(output)
                
                elif cmd == 'ssh_disconnect':
                    success, message = self.ssh_manager.disconnect()
                    print(message)
                
                elif cmd == 'ssh_sessions':
                    sessions = self.ssh_manager.get_active_sessions()
                    if sessions:
                        print("\n🔐 Active SSH Sessions:")
                        for session in sessions:
                            print(f"• {session['host']} ({session['username']})")
                            print(f"  Auth: {session['auth_type']}")
                            print(f"  Connected: {session['connected_at'].strftime('%H:%M:%S')}\n")
                    else:
                        print("📋 No active SSH sessions")
                
                elif cmd == 'generate_traffic' and len(args) >= 2:
                    traffic_type = args[0].lower()
                    target = args[1]
                    result = self.traffic_gen.start_traffic(traffic_type, target)
                    print(result)
                
                elif cmd == 'stop_traffic':
                    result = self.traffic_gen.stop_traffic()
                    print(result)
                
                elif cmd == 'status':
                    cpu = psutil.cpu_percent(interval=1)
                    mem = psutil.virtual_memory()
                    ssh_sessions = len(self.ssh_manager.get_active_sessions())
                    
                    print(f"\n📊 System Status:")
                    print(f"  Bot: {'Online' if self.telegram_token else 'Offline'}")
                    print(f"  SSH Sessions: {ssh_sessions}")
                    print(f"  Traffic Generation: {'Running' if self.traffic_gen.running else 'Stopped'}")
                    print(f"  CPU: {cpu}%")
                    print(f"  Memory: {mem.percent}%")
                
                elif cmd == 'history':
                    history = self.db.get_recent_telegram_commands(20)
                    if history:
                        print("\n📜 Recent Telegram Commands:")
                        for cmd, args, timestamp, username in history:
                            print(f"  [{timestamp}] {username or 'Unknown'}: {cmd} {args}")
                    else:
                        print("📜 No commands recorded")
                
                elif cmd == 'threats':
                    threats = self.db.get_recent_threats(10)
                    if threats:
                        print("\n🚨 Recent Threats:")
                        for ip, ttype, severity, timestamp in threats:
                            print(f"  • {ip}")
                            print(f"    Type: {ttype} | Severity: {severity}")
                            print(f"    Time: {timestamp}\n")
                    else:
                        print("✅ No recent threats detected")
                
                elif cmd == 'telegram_setup':
                    self.setup_telegram()
                    if self.telegram_token and not self.telegram_thread:
                        self.start_telegram_bot()
                
                elif cmd == 'clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.print_banner()
                
                else:
                    print("❌ Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}⚠️ Use 'exit' to quit{Colors.END}")
            except Exception as e:
                print(f"❌ Error: {e}")
                self.db.log_command(command, 'local', False)
    
    def show_help(self):
        """Show help information"""
        help_text = f"""
{Colors.CYAN}{Colors.BOLD}Available Commands:{Colors.END}

{Colors.GREEN}🌐 Network Diagnostics:{Colors.END}
  ping [ip]              - Ping IP address
  tracert [ip]           - Traceroute
  scan [ip] [ports]      - Port scan (default: 1-1000)
  analyze [ip]           - Analyze IP threats
  location [ip]          - Get IP location

{Colors.GREEN}🔐 SSH Operations:{Colors.END}
  ssh_connect [host] [user] [pass] [port] - SSH connect
  ssh_command [cmd]      - Execute SSH command
  ssh_disconnect         - Disconnect SSH
  ssh_sessions           - List SSH sessions

{Colors.GREEN}🌐 Traffic Generation:{Colors.END}
  generate_traffic [tcp|udp|icmp] [target] - Generate traffic
  stop_traffic           - Stop all traffic

{Colors.GREEN}📊 Monitoring:{Colors.END}
  status                 - System status
  history                - Command history
  threats                - Threat summary

{Colors.GREEN}⚙️ System:{Colors.END}
  telegram_setup         - Configure Telegram
  gui                    - Open GUI interface
  clear                  - Clear screen
  help                   - Show this help
  exit                   - Exit program

{Colors.YELLOW}📱 All commands also available via Telegram!{Colors.END}
"""
        print(help_text)
    
    def gui_interface(self):
        """GUI interface for the tool"""
        if not GUI_AVAILABLE:
            print("❌ GUI not available. Install tkinter.")
            return
        
        root = tk.Tk()
        root.title("Accurate Cyber Defense - Telegram Integrated")
        root.geometry("900x700")
        
        # Create notebook for tabs
        notebook = ttk.Notebook(root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Dashboard Tab
        dashboard_frame = ttk.Frame(notebook)
        notebook.add(dashboard_frame, text="Dashboard")
        self.setup_dashboard_tab(dashboard_frame)
        
        # Network Tools Tab
        network_frame = ttk.Frame(notebook)
        notebook.add(network_frame, text="Network Tools")
        self.setup_network_tab(network_frame)
        
        # SSH Client Tab
        ssh_frame = ttk.Frame(notebook)
        notebook.add(ssh_frame, text="SSH Client")
        self.setup_ssh_tab(ssh_frame)
        
        # Traffic Generator Tab
        traffic_frame = ttk.Frame(notebook)
        notebook.add(traffic_frame, text="Traffic Generator")
        self.setup_traffic_tab(traffic_frame)
        
        # Telegram Tab
        telegram_frame = ttk.Frame(notebook)
        notebook.add(telegram_frame, text="Telegram")
        self.setup_telegram_tab(telegram_frame)
        
        # Reports Tab
        reports_frame = ttk.Frame(notebook)
        notebook.add(reports_frame, text="Reports")
        self.setup_reports_tab(reports_frame)
        
        root.mainloop()
    
    def setup_dashboard_tab(self, parent):
        """Setup dashboard tab"""
        # Status frame
        status_frame = ttk.LabelFrame(parent, text="System Status", padding="10")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Status labels
        self.cpu_label = ttk.Label(status_frame, text="CPU: --%")
        self.cpu_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.mem_label = ttk.Label(status_frame, text="Memory: --%")
        self.mem_label.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        
        self.ssh_label = ttk.Label(status_frame, text="SSH Sessions: 0")
        self.ssh_label.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.traffic_label = ttk.Label(status_frame, text="Traffic: Stopped")
        self.traffic_label.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)
        
        self.telegram_label = ttk.Label(status_frame, 
                                       text="Telegram: Disabled" if not self.telegram_token else "Telegram: Active",
                                       foreground="red" if not self.telegram_token else "green")
        self.telegram_label.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)
        
        # Quick actions frame
        actions_frame = ttk.LabelFrame(parent, text="Quick Actions", padding="10")
        actions_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(actions_frame, text="System Status", 
                  command=lambda: self.quick_action("status")).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Scan Localhost", 
                  command=lambda: self.quick_action("scan_local")).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Check Threats", 
                  command=lambda: self.quick_action("threats")).pack(side=tk.LEFT, padx=5)
        
        # Log output frame
        log_frame = ttk.LabelFrame(parent, text="Activity Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Start update thread
        self.update_dashboard()
    
    def setup_network_tab(self, parent):
        """Setup network tools tab"""
        frame = ttk.LabelFrame(parent, text="Network Diagnostics", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Target input
        ttk.Label(frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_entry = ttk.Entry(frame, width=30)
        self.target_entry.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Tool selection
        ttk.Label(frame, text="Tool:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.tool_combo = ttk.Combobox(frame, values=["Ping", "Traceroute", "Port Scan", "Location", "Analyze"], 
                                      state="readonly", width=20)
        self.tool_combo.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        self.tool_combo.current(0)
        
        # Additional options for port scan
        self.port_frame = ttk.Frame(frame)
        self.port_frame.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Label(self.port_frame, text="Port Range:").pack(side=tk.LEFT, padx=5)
        self.port_entry = ttk.Entry(self.port_frame, width=15)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, "1-1000")
        
        # Hide port frame initially
        self.port_frame.grid_remove()
        
        # Bind tool selection change
        self.tool_combo.bind("<<ComboboxSelected>>", self.on_tool_change)
        
        # Execute button
        ttk.Button(frame, text="Execute", command=self.execute_network_tool).grid(row=3, column=0, columnspan=2, pady=10)
        
        # Output area
        ttk.Label(frame, text="Output:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.network_output = scrolledtext.ScrolledText(frame, height=20)
        self.network_output.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(5, weight=1)
    
    def setup_ssh_tab(self, parent):
        """Setup SSH client tab"""
        frame = ttk.LabelFrame(parent, text="SSH Client", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Connection settings
        ttk.Label(frame, text="Host:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ssh_host = ttk.Entry(frame, width=25)
        self.ssh_host.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(frame, text="Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ssh_port = ttk.Entry(frame, width=10)
        self.ssh_port.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        self.ssh_port.insert(0, "22")
        
        ttk.Label(frame, text="Username:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.ssh_user = ttk.Entry(frame, width=20)
        self.ssh_user.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(frame, text="Password:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.ssh_pass = ttk.Entry(frame, width=20, show="*")
        self.ssh_pass.grid(row=3, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Connect", command=self.ssh_connect).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Disconnect", command=self.ssh_disconnect).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="List Sessions", command=self.ssh_list_sessions).pack(side=tk.LEFT, padx=5)
        
        # Command execution
        ttk.Label(frame, text="Command:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.ssh_command = ttk.Entry(frame)
        self.ssh_command.grid(row=5, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.ssh_command.bind("<Return>", lambda e: self.ssh_execute_command())
        
        ttk.Button(frame, text="Execute", command=self.ssh_execute_command).grid(row=6, column=0, columnspan=2, pady=5)
        
        # Output area
        ttk.Label(frame, text="Output:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.ssh_output = scrolledtext.ScrolledText(frame, height=15)
        self.ssh_output.grid(row=8, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(8, weight=1)
    
    def setup_traffic_tab(self, parent):
        """Setup traffic generator tab"""
        frame = ttk.LabelFrame(parent, text="Traffic Generator", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Target configuration
        ttk.Label(frame, text="Target:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.traffic_target = ttk.Entry(frame, width=30)
        self.traffic_target.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(frame, text="Traffic Type:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.traffic_type = ttk.Combobox(frame, values=["TCP", "UDP", "ICMP"], state="readonly", width=15)
        self.traffic_type.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        self.traffic_type.current(0)
        
        ttk.Label(frame, text="Packet Count:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.packet_count = ttk.Entry(frame, width=10)
        self.packet_count.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)
        self.packet_count.insert(0, "100")
        
        ttk.Label(frame, text="Delay (ms):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.traffic_delay = ttk.Entry(frame, width=10)
        self.traffic_delay.grid(row=3, column=1, sticky=tk.W, pady=5, padx=5)
        self.traffic_delay.insert(0, "10")
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Start Traffic", command=self.start_traffic_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Stop Traffic", command=self.stop_traffic_gui).pack(side=tk.LEFT, padx=5)
        
        # Status
        self.traffic_status = ttk.Label(frame, text="Status: Stopped", foreground="red")
        self.traffic_status.grid(row=5, column=0, columnspan=2, pady=5)
        
        # Output area
        ttk.Label(frame, text="Log:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.traffic_output = scrolledtext.ScrolledText(frame, height=15)
        self.traffic_output.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(7, weight=1)
    
    def setup_telegram_tab(self, parent):
        """Setup Telegram tab"""
        frame = ttk.LabelFrame(parent, text="Telegram Bot", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Status
        status_text = "Active" if self.telegram_token else "Disabled"
        status_color = "green" if self.telegram_token else "red"
        
        ttk.Label(frame, text="Status:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.telegram_status = ttk.Label(frame, text=status_text, foreground=status_color)
        self.telegram_status.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        if self.telegram_token:
            ttk.Label(frame, text="Token:").grid(row=1, column=0, sticky=tk.W, pady=5)
            token_display = self.telegram_token[:10] + "..." + self.telegram_token[-10:]
            ttk.Label(frame, text=token_display).grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        if not self.telegram_token:
            ttk.Button(button_frame, text="Configure Telegram", 
                      command=self.setup_telegram_gui).pack(side=tk.LEFT, padx=5)
        else:
            ttk.Button(button_frame, text="Test Bot", 
                      command=self.test_telegram_bot).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Reconfigure", 
                      command=self.setup_telegram_gui).pack(side=tk.LEFT, padx=5)
        
        # Authorized users
        ttk.Label(frame, text="Authorized Users:").grid(row=3, column=0, sticky=tk.W, pady=5)
        
        self.users_tree = ttk.Treeview(frame, columns=("ID", "Username", "Name"), show="headings", height=5)
        self.users_tree.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.users_tree.heading("ID", text="User ID")
        self.users_tree.heading("Username", text="Username")
        self.users_tree.heading("Name", text="Name")
        
        # Recent commands
        ttk.Label(frame, text="Recent Commands:").grid(row=5, column=0, sticky=tk.W, pady=5)
        
        self.commands_tree = ttk.Treeview(frame, columns=("Time", "User", "Command"), show="headings", height=5)
        self.commands_tree.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.commands_tree.heading("Time", text="Time")
        self.commands_tree.heading("User", text="User")
        self.commands_tree.heading("Command", text="Command")
        
        # Refresh button
        ttk.Button(frame, text="Refresh", command=self.refresh_telegram_data).grid(row=7, column=0, columnspan=2, pady=10)
        
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)
        frame.rowconfigure(6, weight=1)
        
        # Initial refresh
        self.refresh_telegram_data()
    
    def setup_reports_tab(self, parent):
        """Setup reports tab"""
        frame = ttk.LabelFrame(parent, text="Reports & Logs", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Report type selection
        ttk.Label(frame, text="Report Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.report_type = ttk.Combobox(frame, values=["Threats", "Network Scans", "SSH Sessions", 
                                                      "Traffic Logs", "Telegram Commands"], state="readonly", width=20)
        self.report_type.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        self.report_type.current(0)
        
        ttk.Label(frame, text="Time Range:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.time_range = ttk.Combobox(frame, values=["Last 24 hours", "Last 7 days", "Last 30 days", "All time"], 
                                      state="readonly", width=15)
        self.time_range.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        self.time_range.current(0)
        
        # Generate button
        ttk.Button(frame, text="Generate Report", command=self.generate_report_gui).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Report output
        ttk.Label(frame, text="Report Output:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.report_output = scrolledtext.ScrolledText(frame, height=20)
        self.report_output.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Save button
        ttk.Button(frame, text="Save Report", command=self.save_report).grid(row=5, column=0, columnspan=2, pady=10)
        
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)
    
    def update_dashboard(self):
        """Update dashboard information"""
        try:
            # Update system info
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            
            self.cpu_label.config(text=f"CPU: {cpu}%")
            self.mem_label.config(text=f"Memory: {mem.percent}%")
            
            # Update SSH sessions
            ssh_sessions = len(self.ssh_manager.get_active_sessions())
            self.ssh_label.config(text=f"SSH Sessions: {ssh_sessions}")
            
            # Update traffic status
            traffic_status = "Running" if self.traffic_gen.running else "Stopped"
            traffic_color = "green" if self.traffic_gen.running else "red"
            self.traffic_label.config(text=f"Traffic: {traffic_status}", foreground=traffic_color)
            
            # Update Telegram status
            telegram_status = "Active" if self.telegram_token else "Disabled"
            telegram_color = "green" if self.telegram_token else "red"
            self.telegram_label.config(text=f"Telegram: {telegram_status}", foreground=telegram_color)
            
            # Add log entry
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_text = f"[{timestamp}] System update: CPU {cpu}%, Mem {mem.percent}%, SSH {ssh_sessions}"
            
            self.log_text.insert(tk.END, log_text + "\n")
            self.log_text.see(tk.END)
            
            # Keep log size manageable
            if int(self.log_text.index('end-1c').split('.')[0]) > 100:
                self.log_text.delete(1.0, 2.0)
            
        except Exception as e:
            logger.error(f"Dashboard update error: {e}")
        
        # Schedule next update
        if hasattr(self, 'root') and self.root.winfo_exists():
            self.root.after(5000, self.update_dashboard)
    
    def on_tool_change(self, event):
        """Handle tool selection change"""
        tool = self.tool_combo.get()
        if tool == "Port Scan":
            self.port_frame.grid()
        else:
            self.port_frame.grid_remove()
    
    def execute_network_tool(self):
        """Execute selected network tool"""
        target = self.target_entry.get().strip()
        tool = self.tool_combo.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.network_output.delete(1.0, tk.END)
        self.network_output.insert(tk.END, f"Executing {tool} on {target}...\n\n")
        
        if tool == "Ping":
            result = self.scanner.ping_ip(target)
        elif tool == "Traceroute":
            result = self.scanner.traceroute(target)
        elif tool == "Port Scan":
            ports = self.port_entry.get().strip() or "1-1000"
            result_obj = self.scanner.port_scan(target, ports)
            if result_obj['success']:
                result = f"Scan Results for {target}:\n\n"
                open_ports = result_obj.get('open_ports', [])
                result += f"Open Ports: {len(open_ports)}\n\n"
                for port in open_ports:
                    result += f"Port {port['port']}: {port['service']}\n"
            else:
                result = f"Scan failed: {result_obj.get('error')}"
        elif tool == "Location":
            result = self.scanner.get_ip_location(target)
        elif tool == "Analyze":
            result = self.scanner.analyze_ip(target)
        else:
            result = "Unknown tool"
        
        self.network_output.insert(tk.END, result)
        self.network_output.see(tk.END)
    
    def ssh_connect(self):
        """SSH connect from GUI"""
        host = self.ssh_host.get().strip()
        port = self.ssh_port.get().strip()
        username = self.ssh_user.get().strip()
        password = self.ssh_pass.get()
        
        if not all([host, username, password]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        try:
            port = int(port) if port else 22
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
            return
        
        success, message = self.ssh_manager.connect_password(host, username, password, port)
        
        self.ssh_output.delete(1.0, tk.END)
        self.ssh_output.insert(tk.END, message + "\n")
        self.ssh_output.see(tk.END)
    
    def ssh_disconnect(self):
        """SSH disconnect from GUI"""
        success, message = self.ssh_manager.disconnect()
        
        self.ssh_output.delete(1.0, tk.END)
        self.ssh_output.insert(tk.END, message + "\n")
        self.ssh_output.see(tk.END)
    
    def ssh_list_sessions(self):
        """List SSH sessions from GUI"""
        sessions = self.ssh_manager.get_active_sessions()
        
        self.ssh_output.delete(1.0, tk.END)
        if sessions:
            self.ssh_output.insert(tk.END, "Active SSH Sessions:\n\n")
            for session in sessions:
                self.ssh_output.insert(tk.END, 
                    f"• {session['host']} ({session['username']})\n"
                    f"  Auth: {session['auth_type']}\n"
                    f"  Connected: {session['connected_at'].strftime('%H:%M:%S')}\n\n")
        else:
            self.ssh_output.insert(tk.END, "No active SSH sessions\n")
        
        self.ssh_output.see(tk.END)
    
    def ssh_execute_command(self):
        """Execute SSH command from GUI"""
        command = self.ssh_command.get().strip()
        if not command:
            return
        
        self.ssh_output.insert(tk.END, f"\n$ {command}\n")
        
        success, output = self.ssh_manager.execute_command(command)
        if success:
            self.ssh_output.insert(tk.END, output + "\n")
        else:
            self.ssh_output.insert(tk.END, f"Error: {output}\n")
        
        self.ssh_command.delete(0, tk.END)
        self.ssh_output.see(tk.END)
    
    def start_traffic_gui(self):
        """Start traffic from GUI"""
        target = self.traffic_target.get().strip()
        traffic_type = self.traffic_type.get().lower()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        try:
            packet_count = int(self.packet_count.get())
            delay = float(self.traffic_delay.get()) / 1000
        except ValueError:
            messagebox.showerror("Error", "Invalid numeric values")
            return
        
        # Start traffic in thread
        def traffic_thread():
            result = self.traffic_gen.start_traffic(traffic_type, target)
            self.traffic_output.insert(tk.END, result + "\n")
            self.traffic_output.see(tk.END)
        
        thread = threading.Thread(target=traffic_thread, daemon=True)
        thread.start()
        
        self.traffic_status.config(text="Status: Running", foreground="green")
    
    def stop_traffic_gui(self):
        """Stop traffic from GUI"""
        result = self.traffic_gen.stop_traffic()
        self.traffic_output.insert(tk.END, result + "\n")
        self.traffic_output.see(tk.END)
        self.traffic_status.config(text="Status: Stopped", foreground="red")
    
    def setup_telegram_gui(self):
        """Setup Telegram from GUI"""
        self.setup_telegram()
        
        if self.telegram_token:
            self.telegram_status.config(text="Active", foreground="green")
            if not self.telegram_thread:
                self.start_telegram_bot()
            self.refresh_telegram_data()
    
    def test_telegram_bot(self):
        """Test Telegram bot from GUI"""
        if not self.telegram_token:
            messagebox.showerror("Error", "Telegram not configured")
            return
        
        messagebox.showinfo("Test", "Bot is active! Send /start to your bot on Telegram.")
    
    def refresh_telegram_data(self):
        """Refresh Telegram data in GUI"""
        # Clear trees
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)
        
        for item in self.commands_tree.get_children():
            self.commands_tree.delete(item)
        
        # Load authorized users
        users = self.db.get_authorized_users()
        for user_id, username, first_name, last_name in users:
            name = f"{first_name or ''} {last_name or ''}".strip()
            self.users_tree.insert("", tk.END, values=(user_id, username or "N/A", name or "N/A"))
        
        # Load recent commands
        commands = self.db.get_recent_telegram_commands(10)
        for cmd, args, timestamp, username in commands:
            display_cmd = f"{cmd} {args}" if args else cmd
            self.commands_tree.insert("", tk.END, values=(timestamp, username or "Unknown", display_cmd))
    
    def generate_report_gui(self):
        """Generate report from GUI"""
        report_type = self.report_type.get()
        time_range = self.time_range.get()
        
        self.report_output.delete(1.0, tk.END)
        self.report_output.insert(tk.END, f"Generating {report_type} report ({time_range})...\n\n")
        
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        if report_type == "Threats":
            cursor.execute('''
                SELECT ip_address, threat_type, severity, description, timestamp 
                FROM threat_logs 
                ORDER BY timestamp DESC LIMIT 50
            ''')
            threats = cursor.fetchall()
            
            self.report_output.insert(tk.END, f"Total threats: {len(threats)}\n\n")
            for ip, ttype, severity, desc, timestamp in threats:
                self.report_output.insert(tk.END, 
                    f"• {ip} - {ttype} ({severity})\n"
                    f"  {desc or 'No description'}\n"
                    f"  {timestamp}\n\n")
        
        elif report_type == "Network Scans":
            cursor.execute('''
                SELECT ip_address, scan_type, open_ports, timestamp 
                FROM scan_results 
                ORDER BY timestamp DESC LIMIT 20
            ''')
            scans = cursor.fetchall()
            
            self.report_output.insert(tk.END, f"Total scans: {len(scans)}\n\n")
            for ip, scan_type, open_ports, timestamp in scans:
                try:
                    ports = json.loads(open_ports) if open_ports else []
                    self.report_output.insert(tk.END, 
                        f"• {ip} - {scan_type}\n"
                        f"  Open ports: {len(ports)}\n"
                        f"  {timestamp}\n\n")
                except:
                    pass
        
        elif report_type == "SSH Sessions":
            cursor.execute('''
                SELECT host, username, port, auth_type, timestamp, successful 
                FROM ssh_sessions 
                ORDER BY timestamp DESC LIMIT 20
            ''')
            sessions = cursor.fetchall()
            
            self.report_output.insert(tk.END, f"Total sessions: {len(sessions)}\n\n")
            for host, user, port, auth, timestamp, success in sessions:
                status = "✅" if success else "❌"
                self.report_output.insert(tk.END, 
                    f"{status} {user}@{host}:{port} ({auth})\n"
                    f"  {timestamp}\n\n")
        
        elif report_type == "Traffic Logs":
            cursor.execute('''
                SELECT traffic_type, target, packets_sent, duration, timestamp 
                FROM traffic_logs 
                ORDER BY timestamp DESC LIMIT 20
            ''')
            logs = cursor.fetchall()
            
            self.report_output.insert(tk.END, f"Total traffic logs: {len(logs)}\n\n")
            for ttype, target, packets, duration, timestamp in logs:
                self.report_output.insert(tk.END, 
                    f"• {ttype} to {target}\n"
                    f"  Packets: {packets}, Duration: {duration:.2f}s\n"
                    f"  {timestamp}\n\n")
        
        elif report_type == "Telegram Commands":
            cursor.execute('''
                SELECT tc.command, tc.arguments, tc.timestamp, tu.username 
                FROM telegram_commands tc
                LEFT JOIN telegram_users tu ON tc.user_id = tu.user_id
                ORDER BY tc.timestamp DESC LIMIT 20
            ''')
            commands = cursor.fetchall()
            
            self.report_output.insert(tk.END, f"Total commands: {len(commands)}\n\n")
            for cmd, args, timestamp, username in commands:
                full_cmd = f"{cmd} {args}" if args else cmd
                self.report_output.insert(tk.END, 
                    f"• {username or 'Unknown'}: {full_cmd}\n"
                    f"  {timestamp}\n\n")
        
        conn.close()
        self.report_output.see(tk.END)
    
    def save_report(self):
        """Save report to file"""
        report_text = self.report_output.get(1.0, tk.END).strip()
        if not report_text:
            messagebox.showerror("Error", "No report to save")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save Report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(report_text)
                messagebox.showinfo("Success", f"Report saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {e}")
    
    def quick_action(self, action: str):
        """Handle quick actions"""
        if action == "status":
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            ssh_sessions = len(self.ssh_manager.get_active_sessions())
            
            status_msg = f"Status:\n• CPU: {cpu}%\n• Memory: {mem.percent}%\n• SSH Sessions: {ssh_sessions}"
            messagebox.showinfo("System Status", status_msg)
        
        elif action == "scan_local":
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                self.target_entry.delete(0, tk.END)
                self.target_entry.insert(0, local_ip)
                self.tool_combo.current(0)  # Ping
                self.execute_network_tool()
            except:
                messagebox.showerror("Error", "Could not determine local IP")
        
        elif action == "threats":
            threats = self.db.get_recent_threats(5)
            if threats:
                threat_msg = "Recent Threats:\n\n"
                for ip, ttype, severity, timestamp in threats:
                    threat_msg += f"• {ip} - {ttype} ({severity})\n"
                messagebox.showwarning("Threats Detected", threat_msg)
            else:
                messagebox.showinfo("No Threats", "No recent threats detected")
    
    def run(self, mode: str = "console"):
        """Run the application in specified mode"""
        self.running = True
        
        if mode == "console":
            self.console_interface()
        elif mode == "gui":
            if GUI_AVAILABLE:
                self.gui_interface()
            else:
                print("❌ GUI not available. Falling back to console mode.")
                self.console_interface()
        else:
            print("❌ Unknown mode. Use 'console' or 'gui'")

# ==================== MAIN ENTRY POINT ====================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Accurate Cyber Defense - Telegram Integrated Tool")
    parser.add_argument('--mode', choices=['console', 'gui'], default='console',
                       help='Interface mode (console or gui)')
    parser.add_argument('--telegram-token', type=str, help='Telegram bot token')
    parser.add_argument('--setup', action='store_true', help='Run setup only')
    
    args = parser.parse_args()
    
    # Check dependencies
    print("🔍 Checking dependencies...")
    
    missing_packages = []
    if not SSH_AVAILABLE:
        missing_packages.append("paramiko")
    if not SCAPY_AVAILABLE:
        missing_packages.append("scapy")
    if not NMAP_AVAILABLE:
        missing_packages.append("python-nmap")
    if not GUI_AVAILABLE and args.mode == "gui":
        missing_packages.append("tkinter")
    
    if missing_packages:
        print(f"⚠️  Missing packages: {', '.join(missing_packages)}")
        print(f"Install with: pip install {' '.join(missing_packages)}")
        print("\nTool will run with limited features.\n")
    
    # Create and run the tool
    tool = CyberDefenseTool()
    
    if args.telegram_token:
        tool.telegram_token = args.telegram_token
        tool.config['telegram_token'] = args.telegram_token
        tool.save_config()
    
    if args.setup:
        tool.setup_telegram()
        print("\n✅ Setup complete!")
        return
    
    try:
        tool.run(args.mode)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
    except Exception as e:
        logger.error(f"Application error: {e}")
        print(f"❌ Application error: {e}")

if __name__ == "__main__":
    main()