#!/usr/bin/env python3
"""
Script de démonstration des fonctionnalités
Montre comment utiliser l'API programmatiquement
"""
import socket
import json
import time
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))
from common.models import Message

class FirewallAPIDemo:
    def __init__(self, host="localhost", port=7890):
        self.host = host
        self.port = port
        self.socket = None
        self.token = None
    
    def connect(self):
        """Connexion au serveur"""
        print(f"🔌 Connecting to {self.host}:{self.port}...")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        print("✅ Connected")
    
    def send_command(self, command, data=None):
        """Envoie une commande et retourne la réponse"""
        if data is None:
            data = {}
        
        data["command"] = command
        
        message = Message(
            type="command",
            data=data,
            session_token=self.token
        )
        
        self.socket.send((message.to_json() + "\n").encode('utf-8'))
        response_data = self.socket.recv(4096).decode('utf-8')
        return Message.from_json(response_data.strip())
    
    def login(self, username, password):
        """Authentification"""
        print(f"\n🔐 Logging in as {username}...")
        response = self.send_command("auth", {
            "username": username,
            "password": password
        })
        
        if response.data.get("success"):
            self.token = response.data["token"]
            print(f"✅ Logged in as {username} ({response.data['user']['role']})")
            return True
        else:
            print(f"❌ Login failed: {response.data.get('message')}")
            return False
    
    def demo_user_management(self):
        """Démonstration de la gestion des utilisateurs"""
        print("\n" + "="*60)
        print("👥 USER MANAGEMENT DEMO")
        print("="*60)
        
        # Lister les utilisateurs
        print("\n📋 Listing users...")
        response = self.send_command("users list")
        if response.data.get("success"):
            users = response.data["users"]
            print(f"Found {len(users)} users:")
            for user in users:
                enabled = "✅" if user["enabled"] else "❌"
                print(f"  {enabled} {user['username']} ({user['role']}) - Firewalls: {user.get('firewalls', [])}")
        
        # Créer un utilisateur
        print("\n➕ Creating user 'demo_user'...")
        response = self.send_command("users create demo_user secret123 editor")
        if response.data.get("success"):
            print(f"✅ {response.data['message']}")
        else:
            print(f"⚠️  {response.data['message']}")
        
        # Désactiver un utilisateur
        print("\n🚫 Disabling user 'demo_user'...")
        response = self.send_command("users disable demo_user")
        if response.data.get("success"):
            print(f"✅ {response.data['message']}")
        
        # Réactiver un utilisateur
        print("\n✅ Enabling user 'demo_user'...")
        response = self.send_command("users enable demo_user")
        if response.data.get("success"):
            print(f"✅ {response.data['message']}")
    
    def demo_firewall_management(self):
        """Démonstration de la gestion des pare-feux"""
        print("\n" + "="*60)
        print("🔥 FIREWALL MANAGEMENT DEMO")
        print("="*60)
        
        # Lister les pare-feux
        print("\n📋 Listing firewalls...")
        response = self.send_command("fw list")
        if response.data.get("success"):
            firewalls = response.data["firewalls"]
            print(f"Found {len(firewalls)} firewalls:")
            for fw in firewalls:
                status_icon = "🟢" if fw["status"] == "active" else "🔴"
                print(f"  {status_icon} {fw['name']} - {fw['status']}")
        
        # Créer des pare-feux
        for fw_name in ["demo_fw1", "demo_fw2", "demo_fw3"]:
            print(f"\n➕ Creating firewall '{fw_name}'...")
            response = self.send_command(f"fw add {fw_name}")
            if response.data.get("success"):
                print(f"✅ {response.data['message']}")
            else:
                print(f"⚠️  {response.data['message']}")
            time.sleep(0.5)
        
        # Vérifier le statut
        print("\n🔍 Checking status of 'demo_fw1'...")
        response = self.send_command("fw status demo_fw1")
        if response.data.get("success"):
            status = response.data["status"]
            print(f"Status: {status}")
        
        # Démarrer un pare-feu
        print("\n🚀 Starting 'demo_fw1'...")
        response = self.send_command("fw start demo_fw1")
        print(f"Result: {response.data.get('message')}")
        
        # Arrêter un pare-feu
        print("\n🛑 Stopping 'demo_fw1'...")
        response = self.send_command("fw stop demo_fw1")
        print(f"Result: {response.data.get('message')}")
    
    def demo_permissions(self):
        """Démonstration du système de permissions"""
        print("\n" + "="*60)
        print("🔒 PERMISSIONS DEMO")
        print("="*60)
        
        print("\n📋 Testing as admin - listing all firewalls...")
        response = self.send_command("fw list")
        if response.data.get("success"):
            print(f"✅ Admin can see {len(response.data['firewalls'])} firewalls")
        
        # Créer un utilisateur avec accès limité
        print("\n➕ Creating limited user 'limited_user'...")
        self.send_command("users create limited_user pass123 editor")
        
        print("\n⚠️  Note: To test limited permissions, reconnect as 'limited_user'")
        print("    They would only see firewalls assigned to them")
    
    def cleanup(self):
        """Nettoyage de la démo"""
        print("\n" + "="*60)
        print("🧹 CLEANUP")
        print("="*60)
        
        # Supprimer les pare-feux de démo
        for fw_name in ["demo_fw1", "demo_fw2", "demo_fw3"]:
            print(f"🗑️  Deleting {fw_name}...")
            response = self.send_command(f"fw delete {fw_name}")
            if response.data.get("success"):
                print(f"✅ Deleted")
        
        # Supprimer les utilisateurs de démo
        for username in ["demo_user", "limited_user"]:
            print(f"🗑️  Deleting user {username}...")
            response = self.send_command(f"users delete {username}")
            if response.data.get("success"):
                print(f"✅ Deleted")
    
    def run_full_demo(self):
        """Exécute la démonstration complète"""
        try:
            self.connect()
            
            if not self.login("admin", "admin"):
                print("❌ Cannot proceed without authentication")
                return
            
            self.demo_user_management()
            time.sleep(1)
            
            self.demo_firewall_management()
            time.sleep(1)
            
            self.demo_permissions()
            time.sleep(1)
            
            input("\n⏸️  Press Enter to cleanup demo data...")
            self.cleanup()
            
            print("\n" + "="*60)
            print("✅ DEMO COMPLETED")
            print("="*60)
            print("\nAll features demonstrated:")
            print("  ✅ User authentication")
            print("  ✅ User management (create, enable, disable, delete)")
            print("  ✅ Firewall management (create, start, stop, status, delete)")
            print("  ✅ Permission system")
            print("  ✅ Session management")
            print("\nCheck data/logs/ for complete activity logs!")
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Demo interrupted")
        except ConnectionRefusedError:
            print("\n❌ Cannot connect to server!")
            print("Make sure the server is running: sudo python3 server/server.py")
        except Exception as e:
            print(f"\n❌ Error: {e}")
        finally:
            if self.socket:
                self.socket.close()
                print("👋 Disconnected")

def main():
    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     🔥 FIREWALL MANAGEMENT SYSTEM - DEMO                 ║
║                                                           ║
║     This demo will showcase all features:                ║
║     • User Management                                    ║
║     • Firewall Management                                ║
║     • Permission System                                  ║
║     • Activity Logging                                   ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    input("Press Enter to start the demo...")
    
    demo = FirewallAPIDemo()
    demo.run_full_demo()

if __name__ == "__main__":
    main()