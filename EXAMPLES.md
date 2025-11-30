# 📚 Exemples d'Utilisation Avancés

Guide pratique avec des cas d'usage réels de l'application de gestion de pare-feux.

## 🎯 Cas d'Usage

### 1. Configuration d'un Serveur Web

**Objectif:** Protéger un serveur web avec des règles iptables basiques.

```bash
# Se connecter
python3 client/client.py -H serveur.example.com -u admin -p

# Créer le pare-feu
fwcli> fw add web-server

# Entrer en mode configuration
fwcli> fw update web-server
fwcli[web-server]> update filter

# Politique par défaut : tout bloquer
fwcli[web-server:filter]> policy INPUT DROP
fwcli[web-server:filter]> policy FORWARD DROP
fwcli[web-server:filter]> policy OUTPUT ACCEPT

# Autoriser le loopback
fwcli[web-server:filter]> add INPUT -i lo ACCEPT

# Autoriser les connexions établies
fwcli[web-server:filter]> add INPUT state RELATED,ESTABLISHED ACCEPT

# Autoriser SSH (port 22)
fwcli[web-server:filter]> add INPUT tcp dport 22 ACCEPT

# Autoriser HTTP (port 80)
fwcli[web-server:filter]> add INPUT tcp dport 80 ACCEPT

# Autoriser HTTPS (port 443)
fwcli[web-server:filter]> add INPUT tcp dport 443 ACCEPT

# Sauvegarder et activer
fwcli[web-server:filter]> bye
fwcli[web-server]> save
fwcli[web-server]> bye
fwcli> fw start web-server
```

### 2. Configuration d'un Serveur de Base de Données

**Objectif:** Limiter l'accès MySQL à des IPs spécifiques.

```bash
fwcli> fw add db-server
fwcli> fw update db-server
fwcli[db-server]> update filter

# Politique par défaut
fwcli[db-server:filter]> policy INPUT DROP
fwcli[db-server:filter]> policy OUTPUT ACCEPT

# Loopback et connexions établies
fwcli[db-server:filter]> add INPUT -i lo ACCEPT
fwcli[db-server:filter]> add INPUT state RELATED,ESTABLISHED ACCEPT

# SSH depuis le réseau admin uniquement
fwcli[db-server:filter]> add INPUT tcp source 192.168.1.0/24 dport 22 ACCEPT

# MySQL depuis les serveurs web uniquement
fwcli[db-server:filter]> add INPUT tcp source 10.0.1.10 dport 3306 ACCEPT
fwcli[db-server:filter]> add INPUT tcp source 10.0.1.11 dport 3306 ACCEPT
fwcli[db-server:filter]> add INPUT tcp source 10.0.1.12 dport 3306 ACCEPT

# Bloquer tout le reste (implicite avec DROP)

fwcli[db-server:filter]> bye
fwcli[db-server]> save
fwcli> fw start db-server
```

### 3. NAT et Redirection de Ports

**Objectif:** Configurer un serveur comme passerelle NAT.

```bash
fwcli> fw add gateway
fwcli> fw update gateway
fwcli[gateway]> update nat

# Activer le NAT pour le réseau local
fwcli[gateway:nat]> add POSTROUTING -o eth0 source 192.168.1.0/24 MASQUERADE

# Redirection de port (port forwarding)
# Rediriger le port 80 externe vers 192.168.1.10:80
fwcli[gateway:nat]> add PREROUTING tcp dport 80 destination 192.168.1.10:80 DNAT

# Rediriger le port 443 externe vers 192.168.1.10:443
fwcli[gateway:nat]> add PREROUTING tcp dport 443 destination 192.168.1.10:443 DNAT

fwcli[gateway:nat]> bye

# Configurer le forwarding
fwcli[gateway]> update filter
fwcli[gateway:filter]> policy FORWARD DROP
fwcli[gateway:filter]> add FORWARD state RELATED,ESTABLISHED ACCEPT
fwcli[gateway:filter]> add FORWARD source 192.168.1.0/24 ACCEPT

fwcli[gateway:filter]> bye
fwcli> fw start gateway
```

### 4. Protection contre les Attaques DDoS

**Objectif:** Limiter les connexions et protéger contre les floods.

```bash
fwcli> fw add anti-ddos
fwcli> fw update anti-ddos
fwcli[anti-ddos]> update filter

# Limiter les nouvelles connexions SSH (max 3/minute)
fwcli[anti-ddos:filter]> add INPUT tcp dport 22 state NEW \
    -m recent --set --name SSH

fwcli[anti-ddos:filter]> add INPUT tcp dport 22 state NEW \
    -m recent --update --seconds 60 --hitcount 4 --name SSH DROP

# Protection contre SYN flood
fwcli[anti-ddos:filter]> add INPUT tcp syn \
    -m limit --limit 1/s --limit-burst 3 ACCEPT

fwcli[anti-ddos:filter]> add INPUT tcp syn DROP

# Bloquer les paquets invalides
fwcli[anti-ddos:filter]> add INPUT state INVALID DROP

# Protection ping flood
fwcli[anti-ddos:filter]> add INPUT icmp icmp-type echo-request \
    -m limit --limit 1/s ACCEPT

fwcli[anti-ddos:filter]> add INPUT icmp icmp-type echo-request DROP

fwcli[anti-ddos:filter]> bye
fwcli> fw start anti-ddos
```

## 👥 Gestion Multi-Utilisateurs

### Scénario: Entreprise avec Plusieurs Administrateurs

**Configuration:**
- Admin principal: accès complet
- Admins systèmes: gestion des serveurs de production
- Développeurs: gestion des serveurs de développement

```bash
# En tant qu'admin principal
fwcli> users create admin-sys1 SecurePass123! admin
fwcli> users create admin-sys2 SecurePass456! admin

fwcli> users create dev-alice DevPass123! editor
fwcli> users create dev-bob DevPass456! editor

# Créer les pare-feux
fwcli> fw add prod-web
fwcli> fw add prod-db
fwcli> fw add prod-api
fwcli> fw add dev-web
fwcli> fw add dev-api

# Assigner les permissions
fwcli> users update dev-alice
fwcli(dev-alice)> fw add dev-web,dev-api
fwcli(dev-alice)> bye

fwcli> users update dev-bob
fwcli(dev-bob)> fw add dev-web,dev-api
fwcli(dev-bob)> bye
```

**Utilisation en tant que développeur:**

```bash
# Alice se connecte
python3 client/client.py -H serveur.example.com -u dev-alice -p

# Elle ne voit que ses pare-feux
fwcli> fw list
🔥 Firewalls:
Name                 Status
------------------------------
dev-web              🔴 inactive
dev-api              🔴 inactive

# Elle ne peut pas gérer les serveurs de production
fwcli> fw start prod-web
❌ Access denied
```

## 🔄 Workflow de Changements

### Scénario: Mise à Jour Sécurisée

**Étape 1: Backup de la configuration actuelle**

```bash
fwcli> fw dump prod-web > backup-prod-web-$(date +%Y%m%d).txt
```

**Étape 2: Test sur environnement de développement**

```bash
fwcli> fw update dev-web
# Appliquer les changements...
fwcli> fw start dev-web
# Tester l'application...
```

**Étape 3: Application en production**

```bash
fwcli> fw update prod-web
# Appliquer les mêmes changements...
fwcli> fw start prod-web
```

**Étape 4: Rollback si nécessaire**

```bash
# Restaurer depuis le backup
fwcli> fw restore prod-web < backup-prod-web-20251125.txt
fwcli> fw start prod-web
```

## 🛠️ Scripts d'Automatisation

### Script Python: Déploiement Automatisé

```python
#!/usr/bin/env python3
"""
Script de déploiement automatisé de configurations pare-feu
"""
import socket
import json
import sys

class FirewallDeployer:
    def __init__(self, host, port=7890):
        self.host = host
        self.port = port
        self.socket = None
        self.token = None
    
    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
    
    def login(self, username, password):
        msg = {
            "type": "command",
            "data": {
                "command": "auth",
                "username": username,
                "password": password
            }
        }
        self.socket.send((json.dumps(msg) + "\n").encode())
        response = json.loads(self.socket.recv(4096).decode().strip())
        
        if response["data"]["success"]:
            self.token = response["data"]["token"]
            return True
        return False
    
    def deploy_web_config(self, firewall_name):
        """Déploie une configuration web standard"""
        
        # Créer le pare-feu
        self.send_command(f"fw add {firewall_name}")
        
        # Configuration standard
        rules = [
            "policy INPUT DROP",
            "policy OUTPUT ACCEPT",
            "add INPUT -i lo ACCEPT",
            "add INPUT state RELATED,ESTABLISHED ACCEPT",
            "add INPUT tcp dport 22 ACCEPT",
            "add INPUT tcp dport 80 ACCEPT",
            "add INPUT tcp dport 443 ACCEPT"
        ]
        
        for rule in rules:
            self.send_command(f"fw {firewall_name} {rule}")
        
        # Activer
        self.send_command(f"fw start {firewall_name}")
        
        print(f"✅ Configuration déployée sur {firewall_name}")
    
    def send_command(self, command):
        msg = {
            "type": "command",
            "data": {"command": command},
            "session_token": self.token
        }
        self.socket.send((json.dumps(msg) + "\n").encode())
        response = json.loads(self.socket.recv(4096).decode().strip())
        return response

# Utilisation
deployer = FirewallDeployer("serveur.example.com")
deployer.connect()
deployer.login("admin", "password")

# Déployer sur plusieurs serveurs
for server in ["web1", "web2", "web3"]:
    deployer.deploy_web_config(server)
```

### Script Bash: Monitoring

```bash
#!/bin/bash
# monitoring.sh - Surveillance des pare-feux

SERVERS=("web1" "web2" "db1" "api1")
ALERT_EMAIL="admin@example.com"

for server in "${SERVERS[@]}"; do
    STATUS=$(python3 client/client.py -H localhost -u monitor -p <<EOF
fw status $server
bye
EOF
)
    
    if [[ $STATUS == *"inactive"* ]]; then
        echo "ALERT: Firewall $server is inactive!" | \
            mail -s "Firewall Alert: $server" $ALERT_EMAIL
    fi
done
```

## 📊 Analyse des Logs

### Script: Extraction des Statistiques

```python
#!/usr/bin/env python3
"""
Analyse les logs et génère des statistiques
"""
import re
from collections import defaultdict
from datetime import datetime

def analyze_logs(log_file):
    stats = {
        'total_commands': 0,
        'by_user': defaultdict(int),
        'by_firewall': defaultdict(int),
        'errors': 0,
        'authentications': 0
    }
    
    with open(log_file, 'r') as f:
        for line in f:
            # Parse la ligne
            match = re.match(r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*)', line)
            if not match:
                continue
            
            timestamp, level, user, message = match.groups()
            
            if level == 'CMD':
                stats['total_commands'] += 1
                
                # Extraire l'utilisateur
                user_parts = user.split('@')
                username = user_parts[0]
                stats['by_user'][username] += 1
                
                # Extraire le pare-feu si présent
                if len(user_parts) > 1:
                    firewall = user_parts[1]
                    stats['by_firewall'][firewall] += 1
            
            elif level == 'ERROR':
                stats['errors'] += 1
            
            elif 'Authentication' in message:
                stats['authentications'] += 1
    
    return stats

# Générer le rapport
stats = analyze_logs('data/logs/firewall_2025-11-25.log')

print("📊 Daily Statistics Report")
print("=" * 50)
print(f"Total Commands: {stats['total_commands']}")
print(f"Authentications: {stats['authentications']}")
print(f"Errors: {stats['errors']}")
print("\nCommands by User:")
for user, count in sorted(stats['by_user'].items(), key=lambda x: x[1], reverse=True):
    print(f"  {user}: {count}")
print("\nCommands by Firewall:")
for fw, count in sorted(stats['by_firewall'].items(), key=lambda x: x[1], reverse=True):
    print(f"  {fw}: {count}")
```

## 🔍 Dépannage Avancé

### Debug Mode

```bash
# Activer les logs détaillés
export FIREWALL_DEBUG=1
python3 server/server.py

# Tracer les commandes iptables
export IPTABLES_TRACE=1
```

### Vérification de Configuration

```python
#!/usr/bin/env python3
"""
Vérifie la cohérence des configurations
"""
import json

def check_firewall_config(firewall_name):
    with open('data/firewalls.json', 'r') as f:
        firewalls = json.load(f)
    
    fw = next((f for f in firewalls if f['name'] == firewall_name), None)
    
    if not fw:
        print(f"❌ Firewall {firewall_name} not found")
        return False
    
    issues = []
    
    # Vérifier qu'il y a au moins une règle
    total_rules = sum(
        len(chains[chain])
        for table in fw['tables'].values()
        for chain, chains in table.items()
    )
    
    if total_rules == 0:
        issues.append("No rules defined")
    
    # Vérifier que SSH est autorisé
    has_ssh = False
    for table in fw['tables'].values():
        for chain, rules in table.items():
            for rule in rules:
                if rule.get('dport') == '22':
                    has_ssh = True
    
    if not has_ssh:
        issues.append("⚠️  WARNING: SSH (port 22) not explicitly allowed")
    
    if issues:
        print(f"Issues found in {firewall_name}:")
        for issue in issues:
            print(f"  - {issue}")
        return False
    
    print(f"✅ {firewall_name} configuration looks good")
    return True

# Vérifier toutes les configs
with open('data/firewalls.json', 'r') as f:
    firewalls = json.load(f)

for fw in firewalls:
    check_firewall_config(fw['name'])
```

## 🎓 Bonnes Pratiques

### 1. Toujours Tester en Dev

```bash
# Ne JAMAIS appliquer directement en prod
fwcli> fw update prod-web  # ❌ Dangereux

# TOUJOURS tester d'abord
fwcli> fw update dev-web   # ✅ Correct
# ... tester ...
fwcli> fw update prod-web  # ✅ Puis appliquer
```

### 2. Documenter les Changements

```bash
# Utiliser des commentaires
fwcli> # Autoriser l'API externe (ticket #1234)
fwcli[srv]> add INPUT tcp source 203.0.113.10 dport 8080 ACCEPT
```

### 3. Sauvegardes Régulières

```bash
# Script de backup quotidien
0 2 * * * cd /opt/firewall-manager && ./backup.sh
```

### 4. Monitoring Continu

```bash
# Alertes automatiques
*/5 * * * * /opt/firewall-manager/monitor.sh
```

---

**Note:** Ces exemples sont des cas d'usage typiques. Adaptez-les selon vos besoins spécifiques et votre environnement réseau.