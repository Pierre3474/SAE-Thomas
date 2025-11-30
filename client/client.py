#!/usr/bin/env python3
"""
Client CLI pour la gestion de pare-feux
"""
import socket
import ssl
import json
import sys
import getpass
import argparse
import hashlib
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from common.models import Message

class FirewallClient:
    def __init__(self, host: str, port: int = 7890, use_ssl: bool = True, verify_cert: bool = False):
        """
        Initialise le client

        Args:
            host: Adresse du serveur
            port: Port du serveur
            use_ssl: Active le chiffrement SSL/TLS
            verify_cert: Vérifie le certificat SSL (False pour les certificats auto-signés)
        """
        self.host = host
        self.port = port
        self.socket = None
        self.session_token = None
        self.username = None
        self.context = []  # Stack de contextes: [], ['srv2'], ['srv2', 'filter']
        self.connected = False
        self.use_ssl = use_ssl
        self.verify_cert = verify_cert
    
    def connect(self):
        """Se connecte au serveur"""
        try:
            # Déterminer la famille de socket (IPv4 ou IPv6) en utilisant getaddrinfo
            # Cela permet de supporter les adresses IPv4 et IPv6 automatiquement
            try:
                addr_info = socket.getaddrinfo(
                    self.host,
                    self.port,
                    socket.AF_UNSPEC,  # IPv4 ou IPv6
                    socket.SOCK_STREAM
                )

                # Prendre la première adresse disponible
                family, socktype, proto, canonname, sockaddr = addr_info[0]

                # Créer le socket TCP avec la bonne famille
                raw_socket = socket.socket(family, socktype, proto)

                # Afficher le type de connexion
                if family == socket.AF_INET6:
                    print(f"🌐 Connecting via IPv6...")
                else:
                    print(f"🌐 Connecting via IPv4...")

            except socket.gaierror as e:
                print(f"❌ Address resolution error: {e}")
                return False

            # Wrapper avec SSL/TLS si activé
            if self.use_ssl:
                try:
                    # Créer le contexte SSL client
                    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

                    if self.verify_cert:
                        # Vérifier le certificat (pour les certificats signés par une CA)
                        ssl_context.check_hostname = True
                        ssl_context.verify_mode = ssl.CERT_REQUIRED
                        ssl_context.load_default_certs()
                    else:
                        # Ne pas vérifier le certificat (pour les certificats auto-signés)
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE

                    # Options de sécurité recommandées
                    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

                    # Wrapper le socket avec SSL
                    self.socket = ssl_context.wrap_socket(
                        raw_socket,
                        server_hostname=self.host if self.verify_cert else None
                    )

                    # Se connecter au serveur
                    self.socket.connect((self.host, self.port))
                    print(f"🔒 Connected with {self.socket.version()}")

                except ssl.SSLError as e:
                    print(f"❌ SSL connection failed: {e}")
                    print(f"💡 Try using --no-ssl flag if the server doesn't support SSL")
                    return False
            else:
                self.socket = raw_socket
                self.socket.connect((self.host, self.port))
                print(f"🔓 Connected without encryption (not recommended)")

            self.connected = True
            return True
        except ConnectionRefusedError:
            print(f"❌ Connection refused. Is the server running on {self.host}:{self.port}?")
            return False
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Se déconnecte du serveur"""
        if self.socket:
            self.socket.close()
            self.connected = False
    
    def send_message(self, command: str, data: dict = None) -> Message:
        """Envoie un message au serveur et attend la réponse"""
        if not self.connected:
            print("❌ Not connected to server")
            return None
        
        if data is None:
            data = {}
        
        data["command"] = command
        
        message = Message(
            type="command",
            data=data,
            session_token=self.session_token
        )
        
        try:
            self.socket.send((message.to_json() + "\n").encode('utf-8'))
            
            # Recevoir la réponse
            response_data = self.socket.recv(4096).decode('utf-8')
            response = Message.from_json(response_data.strip())
            
            return response
        except Exception as e:
            print(f"❌ Communication error: {e}")
            return None
    
    def authenticate(self, username: str, password: str) -> bool:
        """
        S'authentifie auprès du serveur avec Challenge/Réponse

        Étape 1: Demander un challenge au serveur
        Étape 2: Calculer SHA256(challenge + SHA256(password)) et envoyer la réponse
        """
        # Étape 1 : Demander un challenge
        print(f"🔐 Requesting authentication challenge for {username}...")
        challenge_response = self.send_message("auth", {
            "username": username,
            "step": "request_challenge"
        })

        if not challenge_response or not challenge_response.data.get("success"):
            error_msg = challenge_response.data.get("message") if challenge_response else "Failed to get challenge"
            print(f"❌ {error_msg}")
            return False

        # Récupérer le challenge
        challenge = challenge_response.data.get("challenge")
        if not challenge:
            print("❌ No challenge received")
            return False

        # Étape 2 : Calculer la réponse au challenge
        # Hash du mot de passe (comme le fait la base de données)
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        # Hash de (challenge + password_hash)
        response_hash = hashlib.sha256(
            (challenge + password_hash).encode('utf-8')
        ).hexdigest()

        # Envoyer la réponse au serveur
        print(f"🔑 Sending authentication response...")
        auth_response = self.send_message("auth", {
            "username": username,
            "step": "verify_response",
            "response": response_hash
        })

        if auth_response and auth_response.type == "response" and auth_response.data.get("success"):
            self.session_token = auth_response.data.get("token")
            self.username = username
            print(f"✅ {auth_response.data.get('message')}")
            print(f"👤 Logged in as {username} ({auth_response.data['user']['role']})")
            return True
        else:
            error_msg = auth_response.data.get("message") if auth_response else "Authentication failed"
            print(f"❌ {error_msg}")
            return False
    
    def get_prompt(self) -> str:
        """Génère le prompt selon le contexte"""
        if not self.context:
            return "fwcli> "
        elif len(self.context) == 1:
            return f"fwcli[{self.context[0]}]> "
        else:
            return f"fwcli[{':'.join(self.context)}]> "
    
    def handle_command(self, command: str):
        """Gère une commande utilisateur"""
        command = command.strip()

        if not command:
            return True

        # Commandes locales (ne contactent pas le serveur)
        if command in ["exit", "quit", "bye"]:
            if self.context:
                # Sortir du contexte
                self.context.pop()
                print(f"⬅️  Exited context, now at: {self.get_context_display()}")
                return True
            else:
                # Quitter l'application
                self.send_message("logout")
                return False

        if command == "help":
            self.show_help()
            return True

        # Commande pour entrer dans un contexte firewall
        if command.startswith("fw select "):
            parts = command.split()
            if len(parts) >= 3:
                fw_name = parts[2]
                self.context = [fw_name]  # Entrer dans le contexte du firewall
                print(f"➡️  Entered firewall context: {fw_name}")
                print(f"💡 You can now use table-specific commands or 'exit' to go back")
            else:
                print("❌ Usage: fw select <firewall_name>")
            return True

        # Commande pour entrer dans un contexte table (si dans un contexte firewall)
        if command.startswith("table select "):
            if not self.context:
                print("❌ You must select a firewall first (fw select <name>)")
                return True

            parts = command.split()
            if len(parts) >= 3:
                table_name = parts[2]
                if table_name not in ["filter", "nat", "mangle", "raw"]:
                    print(f"❌ Invalid table: {table_name}. Valid: filter, nat, mangle, raw")
                    return True

                # Entrer dans le contexte table
                if len(self.context) == 1:
                    self.context.append(table_name)
                    print(f"➡️  Entered table context: {table_name}")
                    print(f"💡 You can now manage chains for this table or 'exit' to go back")
                else:
                    # Déjà dans un contexte table, le remplacer
                    self.context[1] = table_name
                    print(f"➡️  Switched to table context: {table_name}")
            else:
                print("❌ Usage: table select <table_name>")
            return True

        # Afficher le contexte actuel
        if command == "context":
            if not self.context:
                print("📍 No context selected (root level)")
            elif len(self.context) == 1:
                print(f"📍 Context: Firewall '{self.context[0]}'")
            else:
                print(f"📍 Context: Firewall '{self.context[0]}' > Table '{self.context[1]}'")
            return True

        # Commandes serveur
        if command.startswith("users "):
            return self.handle_users_command(command)
        elif command.startswith("fw "):
            return self.handle_firewall_command(command)
        else:
            print(f"❌ Unknown command: {command}")
            print("Type 'help' for available commands")
            return True

    def get_context_display(self) -> str:
        """Retourne une représentation textuelle du contexte"""
        if not self.context:
            return "root"
        elif len(self.context) == 1:
            return f"firewall '{self.context[0]}'"
        else:
            return f"firewall '{self.context[0]}' > table '{self.context[1]}'"
    
    def handle_users_command(self, command: str) -> bool:
        """Gère les commandes utilisateurs"""
        response = self.send_message(command)
        
        if not response:
            return True
        
        if response.type == "error":
            print(f"❌ {response.data.get('message')}")
        elif response.data.get("success"):
            if "users" in response.data:
                # Liste des utilisateurs
                users = response.data["users"]
                print("\n📋 Users:")
                print(f"{'Username':<15} {'Role':<10} {'Enabled':<10} {'Firewalls'}")
                print("-" * 60)
                for user in users:
                    enabled = "✓" if user["enabled"] else "✗"
                    firewalls = ", ".join(user["firewalls"]) if user["firewalls"] else "-"
                    print(f"{user['username']:<15} {user['role']:<10} {enabled:<10} {firewalls}")
                print()
            else:
                print(f"✅ {response.data.get('message')}")
        
        return True
    
    def handle_firewall_command(self, command: str) -> bool:
        """Gère les commandes pare-feu"""
        response = self.send_message(command)
        
        if not response:
            return True
        
        if response.type == "error":
            print(f"❌ {response.data.get('message')}")
        elif response.data.get("success"):
            if "firewalls" in response.data:
                # Liste des pare-feux
                firewalls = response.data["firewalls"]
                print("\n🔥 Firewalls:")
                print(f"{'Name':<20} {'Status':<10}")
                print("-" * 30)
                for fw in firewalls:
                    status_icon = "🟢" if fw["status"] == "active" else "🔴"
                    print(f"{fw['name']:<20} {status_icon} {fw['status']:<10}")
                print()
            elif "status" in response.data:
                # Status d'un pare-feu
                status = response.data["status"]
                name = response.data["name"]
                status_icon = "🟢" if status == "active" else "🔴"
                print(f"{status_icon} Firewall {name}: {status}")
            else:
                print(f"✅ {response.data.get('message')}")
        
        return True
    
    def show_help(self):
        """Affiche l'aide"""
        print("\n📖 Available commands:")
        print("\n🔐 Authentication:")
        print("  (authentication is done at startup)")

        print("\n👥 User management (admin only):")
        print("  users list                    - List all users")
        print("  users create <user> <pass>    - Create a new user")
        print("  users enable <user>           - Enable a user")
        print("  users disable <user>          - Disable a user")
        print("  users delete <user>           - Delete a user")

        print("\n🔥 Firewall management:")
        print("  fw list                       - List all firewalls")
        print("  fw add <name>                 - Create a new firewall")
        print("  fw delete <name>              - Delete a firewall")
        print("  fw start <name>               - Start/activate a firewall")
        print("  fw stop <name>                - Stop/deactivate a firewall")
        print("  fw status <name>              - Show firewall status")
        print("  fw select <name>              - Enter firewall context (local)")

        print("\n🗂️  Context navigation (local, no server contact):")
        print("  fw select <name>              - Enter firewall context")
        print("  table select <table>          - Enter table context (filter/nat/mangle/raw)")
        print("  context                       - Show current context")
        print("  exit/back                     - Exit current context level")

        print("\n🚪 General:")
        print("  help                          - Show this help")
        print("  bye/exit/quit                 - Exit (or exit context)")
        print()
    
    def run_interactive(self):
        """Mode interactif"""
        print("🔥 Firewall Management Client")
        print(f"Connected to {self.host}:{self.port}\n")
        
        try:
            while True:
                try:
                    command = input(self.get_prompt())
                    if not self.handle_command(command):
                        break
                except EOFError:
                    print("\nbye")
                    break
                except KeyboardInterrupt:
                    print("\nUse 'bye' to exit")
                    continue
        finally:
            self.disconnect()
            print("👋 Goodbye!")

def main():
    parser = argparse.ArgumentParser(description="Firewall Management Client")
    parser.add_argument("-H", "--host", required=True, help="Server hostname")
    parser.add_argument("-P", "--port", type=int, default=7890, help="Server port")
    parser.add_argument("-u", "--username", help="Username")
    parser.add_argument("-p", "--password", action="store_true", help="Prompt for password")
    parser.add_argument("--no-ssl", action="store_true", help="Disable SSL/TLS encryption")
    parser.add_argument("--verify-cert", action="store_true", help="Verify SSL certificate (for CA-signed certs)")

    args = parser.parse_args()

    client = FirewallClient(
        args.host,
        args.port,
        use_ssl=not args.no_ssl,
        verify_cert=args.verify_cert
    )
    
    if not client.connect():
        sys.exit(1)
    
    # Authentification
    if args.username:
        if args.password:
            password = getpass.getpass("password: ")
        else:
            password = input("password: ")
        
        if not client.authenticate(args.username, password):
            sys.exit(1)
    else:
        print("Please provide username with -u option")
        sys.exit(1)
    
    # Mode interactif
    client.run_interactive()

if __name__ == "__main__":
    main()