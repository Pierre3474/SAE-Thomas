#!/usr/bin/env python3
"""
Client CLI pour la gestion de pare-feux
"""
import socket
import json
import sys
import getpass
import argparse
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from common.models import Message

class FirewallClient:
    def __init__(self, host: str, port: int = 7890):
        self.host = host
        self.port = port
        self.socket = None
        self.session_token = None
        self.username = None
        self.context = []  # Stack de contextes: [], ['srv2'], ['srv2', 'filter']
        self.connected = False
    
    def connect(self):
        """Se connecte au serveur"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            return True
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
        """S'authentifie auprès du serveur"""
        response = self.send_message("auth", {
            "username": username,
            "password": password
        })
        
        if response and response.type == "response" and response.data.get("success"):
            self.session_token = response.data.get("token")
            self.username = username
            print(f"✅ {response.data.get('message')}")
            print(f"👤 Logged in as {username} ({response.data['user']['role']})")
            return True
        else:
            error_msg = response.data.get("message") if response else "Authentication failed"
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
        
        # Commandes locales
        if command in ["exit", "quit", "bye"]:
            if self.context:
                # Sortir du contexte
                self.context.pop()
                return True
            else:
                # Quitter l'application
                self.send_message("logout")
                return False
        
        if command == "help":
            self.show_help()
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
    
    args = parser.parse_args()
    
    client = FirewallClient(args.host, args.port)
    
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