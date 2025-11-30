"""
Serveur TCP multi-clients pour la gestion de pare-feux
"""
import socket
import threading
import json
import secrets
from datetime import datetime
from typing import Dict, Optional
import sys
import os
from pathlib import Path

# Ajouter le répertoire parent au PYTHONPATH
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
sys.path.insert(0, str(parent_dir))

from common.models import Message, User, UserRole, FirewallStatus
from server.database import Database
from server.logger import get_logger
from server.iptables import IptablesManager

class Session:
    """Représente une session utilisateur"""
    def __init__(self, user: User, token: str):
        self.user = user
        self.token = token
        self.created_at = datetime.now()
        self.last_activity = datetime.now()

class FirewallServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 7890):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        
        self.db = Database()
        self.logger = get_logger()
        self.iptables = IptablesManager()
        
        # Sessions actives: token -> Session
        self.sessions: Dict[str, Session] = {}
        self.sessions_lock = threading.Lock()
        
        self.logger.info("SYSTEM", f"Server initialized on {host}:{port}")
    
    def start(self):
        """Démarre le serveur"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        self.running = True
        self.logger.info("SYSTEM", f"Server listening on {self.host}:{self.port}")
        
        print(f"🔥 Firewall Management Server started on {self.host}:{self.port}")
        print("Press Ctrl+C to stop")
        
        try:
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.logger.info("SYSTEM", f"New connection from {client_address}")
                    
                    # Créer un thread pour gérer ce client
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    self.logger.error("SYSTEM", f"Error accepting connection: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Arrête le serveur"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("SYSTEM", "Server stopped")
        print("\n🛑 Server stopped")
    
    def handle_client(self, client_socket: socket.socket, client_address):
        """Gère un client connecté"""
        try:
            while self.running:
                # Recevoir les données
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                # Parser le message
                try:
                    message = Message.from_json(data)
                    response = self.process_message(message, client_address[0])
                    
                    # Envoyer la réponse
                    client_socket.send((response.to_json() + "\n").encode('utf-8'))
                except json.JSONDecodeError:
                    error_response = Message(
                        type="error",
                        data={"message": "Invalid JSON format"}
                    )
                    client_socket.send((error_response.to_json() + "\n").encode('utf-8'))
        except Exception as e:
            self.logger.error("SYSTEM", f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            self.logger.info("SYSTEM", f"Connection closed from {client_address}")
    
    def process_message(self, message: Message, client_ip: str) -> Message:
        """Traite un message reçu du client"""
        
        # Commande d'authentification
        if message.data.get("command") == "auth":
            return self.handle_auth(message, client_ip)
        
        # Vérifier la session pour toutes les autres commandes
        session = self.get_session(message.session_token)
        if not session:
            return Message(
                type="error",
                data={"message": "Invalid or expired session. Please authenticate."}
            )
        
        # Mettre à jour l'activité de la session
        session.last_activity = datetime.now()
        
        # Router la commande
        command = message.data.get("command")
        
        if command.startswith("users "):
            return self.handle_users_command(message, session)
        elif command.startswith("fw "):
            return self.handle_firewall_command(message, session)
        elif command == "logout":
            return self.handle_logout(message, session)
        else:
            return Message(
                type="error",
                data={"message": f"Unknown command: {command}"}
            )
    
    def handle_auth(self, message: Message, client_ip: str) -> Message:
        """Gère l'authentification"""
        username = message.data.get("username")
        password = message.data.get("password")
        
        if not username or not password:
            return Message(
                type="error",
                data={"message": "Username and password required"}
            )
        
        user = self.db.authenticate(username, password)
        
        if user:
            # Créer une session
            token = secrets.token_hex(32)
            session = Session(user, token)
            
            with self.sessions_lock:
                self.sessions[token] = session
            
            self.logger.auth_success(username, client_ip)
            
            return Message(
                type="response",
                data={
                    "success": True,
                    "message": "Authentication successful",
                    "token": token,
                    "user": {
                        "username": user.username,
                        "role": user.role.value
                    }
                }
            )
        else:
            self.logger.auth_failed(username, client_ip)
            return Message(
                type="error",
                data={"message": "Invalid username or password"}
            )
    
    def handle_logout(self, message: Message, session: Session) -> Message:
        """Gère la déconnexion"""
        with self.sessions_lock:
            if message.session_token in self.sessions:
                del self.sessions[message.session_token]
        
        self.logger.info(session.user.username, "Logged out")
        
        return Message(
            type="response",
            data={"success": True, "message": "Logged out successfully"}
        )
    
    def handle_users_command(self, message: Message, session: Session) -> Message:
        """Gère les commandes utilisateurs"""
        command = message.data.get("command")
        user = session.user
        
        # Seuls les admins peuvent gérer les utilisateurs
        if user.role != UserRole.ADMIN:
            self.logger.error(user.username, f"Permission denied: {command}")
            return Message(
                type="error",
                data={"message": "Permission denied. Admin role required."}
            )
        
        self.logger.command(user.username, command)
        
        parts = command.split()
        
        if parts[1] == "list":
            users = self.db.load_users()
            return Message(
                type="response",
                data={
                    "success": True,
                    "users": [
                        {
                            "username": u.username,
                            "role": u.role.value,
                            "enabled": u.enabled,
                            "firewalls": u.firewalls
                        }
                        for u in users
                    ]
                }
            )
        
        elif parts[1] == "create" and len(parts) >= 4:
            username = parts[2]
            password = parts[3]
            role = UserRole(parts[4]) if len(parts) > 4 else UserRole.EDITOR
            
            try:
                new_user = self.db.create_user(username, password, role)
                return Message(
                    type="response",
                    data={"success": True, "message": f"User {username} created"}
                )
            except ValueError as e:
                return Message(type="error", data={"message": str(e)})
        
        elif parts[1] in ["enable", "disable"] and len(parts) >= 3:
            username = parts[2]
            enabled = parts[1] == "enable"
            
            try:
                self.db.update_user(username, enabled=enabled)
                action = "enabled" if enabled else "disabled"
                return Message(
                    type="response",
                    data={"success": True, "message": f"User {username} {action}"}
                )
            except ValueError as e:
                return Message(type="error", data={"message": str(e)})
        
        elif parts[1] == "delete" and len(parts) >= 3:
            username = parts[2]
            self.db.delete_user(username)
            return Message(
                type="response",
                data={"success": True, "message": f"User {username} deleted"}
            )
        
        return Message(type="error", data={"message": "Invalid users command"})
    
    def handle_firewall_command(self, message: Message, session: Session) -> Message:
        """Gère les commandes pare-feu"""
        command = message.data.get("command")
        user = session.user
        
        self.logger.command(user.username, command)
        
        parts = command.split()
        
        if parts[1] == "list":
            firewalls = self.db.load_firewalls()
            # Filtrer selon les permissions
            if user.role != UserRole.ADMIN:
                firewalls = [fw for fw in firewalls if user.has_access(fw.name)]
            
            return Message(
                type="response",
                data={
                    "success": True,
                    "firewalls": [
                        {
                            "name": fw.name,
                            "status": fw.status.value
                        }
                        for fw in firewalls
                    ]
                }
            )
        
        elif parts[1] == "add" and len(parts) >= 3:
            fw_name = parts[2]
            
            try:
                fw = self.db.create_firewall(fw_name)
                return Message(
                    type="response",
                    data={"success": True, "message": f"Firewall {fw_name} created"}
                )
            except ValueError as e:
                return Message(type="error", data={"message": str(e)})
        
        elif parts[1] in ["start", "stop", "status"] and len(parts) >= 3:
            fw_name = parts[2]
            
            # Vérifier les permissions
            if not user.has_access(fw_name):
                return Message(type="error", data={"message": "Access denied"})
            
            fw = self.db.get_firewall(fw_name)
            if not fw:
                return Message(type="error", data={"message": f"Firewall {fw_name} not found"})
            
            if parts[1] == "status":
                return Message(
                    type="response",
                    data={
                        "success": True,
                        "status": fw.status.value,
                        "name": fw.name
                    }
                )
            elif parts[1] == "start":
                success, msg = self.iptables.load_firewall_config(fw)
                if success:
                    fw.status = FirewallStatus.ACTIVE
                    self.db.update_firewall(fw)
                return Message(
                    type="response",
                    data={"success": success, "message": msg}
                )
            elif parts[1] == "stop":
                success, msg = self.iptables.flush_all("filter")
                if success:
                    fw.status = FirewallStatus.INACTIVE
                    self.db.update_firewall(fw)
                return Message(
                    type="response",
                    data={"success": success, "message": msg}
                )
        
        return Message(type="error", data={"message": "Invalid firewall command"})
    
    def get_session(self, token: Optional[str]) -> Optional[Session]:
        """Récupère une session par son token"""
        if not token:
            return None
        
        with self.sessions_lock:
            return self.sessions.get(token)

if __name__ == "__main__":
    server = FirewallServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()