#!/usr/bin/env python3
"""
Serveur HTTP pour l'interface web avec API REST
"""
import http.server
import socketserver
import json
import threading
from urllib.parse import urlparse, parse_qs
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from server.database import Database
from server.logger import get_logger
from server.iptables import IptablesManager
from common.models import UserRole, FirewallStatus

class FirewallHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Handler HTTP personnalisé avec API REST"""
    
    def __init__(self, *args, db=None, logger=None, iptables=None, **kwargs):
        self.db = db
        self.logger = logger
        self.iptables = iptables
        self.sessions = {}
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Gère les requêtes GET"""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/':
            # Servir l'interface web
            self.serve_file('web/index.html')
        elif parsed_path.path.startswith('/api/'):
            self.handle_api_request('GET', parsed_path)
        else:
            super().do_GET()
    
    def do_POST(self):
        """Gère les requêtes POST"""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path.startswith('/api/'):
            self.handle_api_request('POST', parsed_path)
        else:
            self.send_error(404)
    
    def handle_api_request(self, method, parsed_path):
        """Route les requêtes API"""
        path = parsed_path.path
        
        try:
            # Lire le corps de la requête pour POST
            if method == 'POST':
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
            else:
                data = {}
            
            # Router les endpoints
            if path == '/api/auth':
                response = self.handle_auth(data)
            elif path == '/api/users':
                response = self.handle_users(data)
            elif path == '/api/firewalls':
                response = self.handle_firewalls(data)
            elif path == '/api/firewall/start':
                response = self.handle_firewall_action(data, 'start')
            elif path == '/api/firewall/stop':
                response = self.handle_firewall_action(data, 'stop')
            elif path == '/api/firewall/status':
                response = self.handle_firewall_action(data, 'status')
            elif path == '/api/logs':
                response = self.handle_logs(data)
            else:
                response = {'error': 'Unknown endpoint'}
            
            self.send_json_response(response)
            
        except Exception as e:
            self.send_json_response({'error': str(e)}, status=500)
    
    def handle_auth(self, data):
        """Authentification"""
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return {'error': 'Username and password required'}
        
        user = self.db.authenticate(username, password)
        
        if user:
            import secrets
            token = secrets.token_hex(32)
            self.sessions[token] = user
            
            self.logger.auth_success(username, self.client_address[0])
            
            return {
                'success': True,
                'token': token,
                'user': {
                    'username': user.username,
                    'role': user.role.value
                }
            }
        else:
            self.logger.auth_failed(username, self.client_address[0])
            return {'error': 'Invalid credentials'}
    
    def handle_users(self, data):
        """Gestion des utilisateurs"""
        token = data.get('token')
        user = self.sessions.get(token)
        
        if not user or user.role != UserRole.ADMIN:
            return {'error': 'Unauthorized'}
        
        action = data.get('action')
        
        if action == 'list':
            users = self.db.load_users()
            return {
                'success': True,
                'users': [
                    {
                        'username': u.username,
                        'role': u.role.value,
                        'enabled': u.enabled,
                        'firewalls': u.firewalls
                    }
                    for u in users
                ]
            }
        elif action == 'create':
            username = data.get('username')
            password = data.get('password')
            role = UserRole(data.get('role', 'editor'))
            
            try:
                self.db.create_user(username, password, role)
                self.logger.command(user.username, f"Created user {username}")
                return {'success': True, 'message': f'User {username} created'}
            except ValueError as e:
                return {'error': str(e)}
        
        elif action == 'enable':
            username = data.get('username')
            self.db.update_user(username, enabled=True)
            self.logger.command(user.username, f"Enabled user {username}")
            return {'success': True, 'message': f'User {username} enabled'}
        
        elif action == 'disable':
            username = data.get('username')
            self.db.update_user(username, enabled=False)
            self.logger.command(user.username, f"Disabled user {username}")
            return {'success': True, 'message': f'User {username} disabled'}
        
        return {'error': 'Invalid action'}
    
    def handle_firewalls(self, data):
        """Gestion des pare-feux"""
        token = data.get('token')
        user = self.sessions.get(token)
        
        if not user:
            return {'error': 'Unauthorized'}
        
        action = data.get('action')
        
        if action == 'list':
            firewalls = self.db.load_firewalls()
            
            # Filtrer selon permissions
            if user.role != UserRole.ADMIN:
                firewalls = [fw for fw in firewalls if user.has_access(fw.name)]
            
            return {
                'success': True,
                'firewalls': [
                    {
                        'name': fw.name,
                        'status': fw.status.value
                    }
                    for fw in firewalls
                ]
            }
        
        elif action == 'create':
            name = data.get('name')
            try:
                self.db.create_firewall(name)
                self.logger.command(user.username, f"Created firewall {name}")
                return {'success': True, 'message': f'Firewall {name} created'}
            except ValueError as e:
                return {'error': str(e)}
        
        elif action == 'delete':
            name = data.get('name')
            if not user.has_access(name):
                return {'error': 'Access denied'}
            
            self.db.delete_firewall(name)
            self.logger.command(user.username, f"Deleted firewall {name}")
            return {'success': True, 'message': f'Firewall {name} deleted'}
        
        return {'error': 'Invalid action'}
    
    def handle_firewall_action(self, data, action):
        """Actions sur un pare-feu"""
        token = data.get('token')
        user = self.sessions.get(token)
        
        if not user:
            return {'error': 'Unauthorized'}
        
        name = data.get('name')
        
        if not user.has_access(name):
            return {'error': 'Access denied'}
        
        fw = self.db.get_firewall(name)
        if not fw:
            return {'error': f'Firewall {name} not found'}
        
        if action == 'status':
            return {
                'success': True,
                'status': fw.status.value,
                'name': fw.name
            }
        
        elif action == 'start':
            success, msg = self.iptables.load_firewall_config(fw)
            if success:
                fw.status = FirewallStatus.ACTIVE
                self.db.update_firewall(fw)
                self.logger.command(user.username, f"Started firewall {name}", name)
            return {'success': success, 'message': msg}
        
        elif action == 'stop':
            success, msg = self.iptables.flush_all("filter")
            if success:
                fw.status = FirewallStatus.INACTIVE
                self.db.update_firewall(fw)
                self.logger.command(user.username, f"Stopped firewall {name}", name)
            return {'success': success, 'message': msg}
        
        return {'error': 'Invalid action'}
    
    def handle_logs(self, data):
        """Récupération des logs"""
        token = data.get('token')
        user = self.sessions.get(token)
        
        if not user:
            return {'error': 'Unauthorized'}
        
        logs = self.logger.get_recent_logs(50)
        return {
            'success': True,
            'logs': [log.strip() for log in logs]
        }
    
    def send_json_response(self, data, status=200):
        """Envoie une réponse JSON"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
    
    def serve_file(self, filepath):
        """Sert un fichier statique"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            
            if filepath.endswith('.html'):
                self.send_header('Content-Type', 'text/html')
            elif filepath.endswith('.css'):
                self.send_header('Content-Type', 'text/css')
            elif filepath.endswith('.js'):
                self.send_header('Content-Type', 'application/javascript')
            
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404)
    
    def log_message(self, format, *args):
        """Override pour logger les requêtes HTTP"""
        pass

class FirewallWebServer:
    def __init__(self, port=8080):
        self.port = port
        self.db = Database()
        self.logger = get_logger()
        self.iptables = IptablesManager()
        
        # Créer un handler avec les dépendances injectées
        def handler(*args, **kwargs):
            return FirewallHTTPHandler(
                *args,
                db=self.db,
                logger=self.logger,
                iptables=self.iptables,
                **kwargs
            )
        
        self.httpd = socketserver.TCPServer(("", port), handler)
    
    def start(self):
        """Démarre le serveur web"""
        print(f"🌐 Web Server started on http://0.0.0.0:{self.port}")
        print(f"📱 Open http://localhost:{self.port} in your browser")
        self.httpd.serve_forever()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Firewall Management Web Server")
    parser.add_argument("-p", "--port", type=int, default=8080, help="HTTP port")
    
    args = parser.parse_args()
    
    server = FirewallWebServer(args.port)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")

if __name__ == "__main__":
    main()