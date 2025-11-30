# 🔥 Application de Gestion de Pare-feux iptables

Application client/serveur en Python pour gérer des pare-feux iptables de manière centralisée.

## 📋 Fonctionnalités

### ✅ Implémenté
- ✅ Serveur TCP multi-clients (port 7890)
- ✅ Authentification des utilisateurs avec sessions
- ✅ Gestion complète des utilisateurs (CRUD)
- ✅ Système de rôles (Admin, Editor, Reader)
- ✅ Gestion des pare-feux (création, suppression, démarrage, arrêt)
- ✅ Interface iptables réelle (modification du système)
- ✅ Journalisation complète horodatée
- ✅ Client CLI interactif
- ✅ Interface Web moderne

### 🔜 En option (à implémenter)
- ⏳ Chiffrement TLS
- ⏳ Support IPv6
- ⏳ Rollback des commandes

## 📁 Structure du Projet

```
firewall-manager/
├── server/
│   ├── server.py          # Serveur TCP principal
│   ├── database.py        # Gestion des données
│   ├── logger.py          # Système de logs
│   └── iptables.py        # Interface iptables
├── client/
│   └── client.py          # Client CLI
├── common/
│   └── models.py          # Modèles de données
├── data/
│   ├── users.json         # Base utilisateurs
│   ├── firewalls.json     # Configurations
│   └── logs/              # Fichiers de logs
└── web/
    └── index.html         # Interface web
```

## 🚀 Installation

### Prérequis
- Python 3.8+
- Linux avec iptables installé
- Droits root pour modifier iptables

### Installation

```bash
# Cloner le projet
git clone <repo-url>
cd firewall-manager

# Créer les répertoires
mkdir -p data/logs

# Aucune dépendance externe nécessaire (Python standard library)
```

## 🎯 Utilisation

### 1. Démarrer le Serveur

```bash
# Avec sudo pour accès iptables
sudo python3 server/server.py
```

Le serveur démarre sur `0.0.0.0:7890` avec un utilisateur admin par défaut :
- **Username:** `admin`
- **Password:** `admin`

⚠️ **Changez ce mot de passe en production !**

### 2. Utiliser le Client CLI

```bash
# Se connecter au serveur
python3 client/client.py -H localhost -u admin -p
password: admin

# Commandes disponibles
fwcli> help                        # Afficher l'aide
fwcli> users list                  # Lister les utilisateurs
fwcli> users create bob secret123  # Créer un utilisateur
fwcli> fw list                     # Lister les pare-feux
fwcli> fw add srv1                 # Créer un pare-feu
fwcli> fw start srv1               # Démarrer le pare-feu
fwcli> fw stop srv1                # Arrêter le pare-feu
fwcli> fw status srv1              # Voir le statut
fwcli> bye                         # Quitter
```

### 3. Interface Web

Ouvrir `web/index.html` dans un navigateur moderne.

**Credentials par défaut:**
- Username: `admin`
- Password: `admin`

## 👥 Gestion des Utilisateurs

### Rôles Disponibles

| Rôle | Permissions |
|------|-------------|
| **Admin** | Tous les droits (users + firewalls) |
| **Editor** | Gestion des pare-feux assignés |
| **Reader** | Consultation uniquement |

### Commandes Utilisateurs (Admin seulement)

```bash
# Lister tous les utilisateurs
users list

# Créer un utilisateur (role par défaut: editor)
users create <username> <password>

# Activer/Désactiver un utilisateur
users enable <username>
users disable <username>

# Supprimer un utilisateur
users delete <username>

# Voir les infos d'un utilisateur
users infos <username>
```

## 🔥 Gestion des Pare-feux

### Commandes Pare-feu

```bash
# Lister les pare-feux (selon permissions)
fw list

# Créer un nouveau pare-feu
fw add <name>

# Supprimer un pare-feu
fw delete <name>

# Démarrer (appliquer les règles)
fw start <name>

# Arrêter (flush les règles)
fw stop <name>

# Voir le statut
fw status <name>
```

### Fonctionnement iptables

Le système gère 3 tables principales :
- **filter** : INPUT, OUTPUT, FORWARD
- **nat** : PREROUTING, POSTROUTING, OUTPUT
- **mangle** : PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING

## 📝 Système de Logs

Les logs sont automatiquement sauvegardés dans `data/logs/` avec un fichier par jour.

**Format:** `[TIMESTAMP] [LEVEL] [USER@FIREWALL] MESSAGE`

**Exemple:**
```
[2025-11-25 10:30:15] [INFO] [admin] Authentication successful from 127.0.0.1
[2025-11-25 10:30:22] [CMD] [alice@srv2] fw start srv2
[2025-11-25 10:30:25] [ERROR] [bob] Permission denied: fw delete srv1
```

## 🔒 Sécurité

### Authentification
- Mots de passe hashés en SHA-256
- Sessions avec tokens aléatoires
- Timeout de session automatique

### Permissions
- Vérification des droits à chaque commande
- Isolation des pare-feux par utilisateur
- Seuls les admins gèrent les users

### Iptables
- Exécution réelle des commandes
- Nécessite les droits root
- Validation des commandes avant exécution

## 🧪 Tests

### Tester le serveur

```bash
# Terminal 1: Démarrer le serveur
sudo python3 server/server.py

# Terminal 2: Tester avec le client
python3 client/client.py -H localhost -u admin -p
```

### Scénario de test complet

```bash
# 1. Se connecter en admin
fwcli> users list
fwcli> users create alice password123

# 2. Créer des pare-feux
fwcli> fw add srv1
fwcli> fw add srv2
fwcli> fw list

# 3. Assigner des droits
fwcli> users update alice
fwcli(alice)> fw list
fwcli(alice)> add srv1
fwcli(alice)> bye

# 4. Tester avec alice
# (Nouvelle connexion)
fwcli> fw list    # Ne voit que srv1
fwcli> fw start srv1
fwcli> fw status srv1
```

## 🐛 Dépannage

### Le serveur ne démarre pas
- Vérifier que le port 7890 est libre: `netstat -ln | grep 7890`
- Vérifier les permissions d'écriture dans `data/`

### Erreur "Permission denied" pour iptables
- Lancer le serveur avec `sudo`
- Vérifier que iptables est installé: `which iptables`

### Le client ne se connecte pas
- Vérifier que le serveur est démarré
- Vérifier le hostname/IP et le port
- Tester avec: `telnet localhost 7890`

## 📊 Architecture

```
┌─────────────┐         TCP 7890        ┌──────────────┐
│   Client    │◄───────────────────────►│   Serveur    │
│   CLI/Web   │      JSON Messages      │   TCP        │
└─────────────┘                         └──────┬───────┘
                                               │
                                    ┌──────────┼──────────┐
                                    │          │          │
                                ┌───▼───┐  ┌───▼────┐  ┌─▼──────┐
                                │ Auth  │  │ Users  │  │ iptables│
                                └───────┘  └────────┘  └────────┘
                                    │          │          │
                                ┌───▼──────────▼──────────▼────┐
                                │      Database (JSON)         │
                                │   users.json / firewalls.json│
                                └──────────────────────────────┘
```

## 📚 Protocole de Communication

Messages en JSON sur TCP:

```json
{
  "type": "command",
  "data": {
    "command": "fw list"
  },
  "session_token": "abc123...",
  "timestamp": "2025-11-25T10:30:00"
}
```

Réponses:
```json
{
  "type": "response",
  "data": {
    "success": true,
    "firewalls": [...]
  },
  "timestamp": "2025-11-25T10:30:01"
}
```

## 🔮 Améliorations Futures

- [ ] TLS/SSL pour chiffrement
- [ ] Support IPv6
- [ ] Rollback automatique des règles
- [ ] Export/Import de configurations
- [ ] Interface web avec WebSocket temps réel
- [ ] Dashboard de monitoring
- [ ] Notifications par email
- [ ] API REST en complément du TCP
- [ ] Support de nftables

## 📄 Licence

Ce projet est développé dans un cadre éducatif.

## 👨‍💻 Auteur

Développé pour le projet de gestion de pare-feux.

---

**Note:** Cette application modifie réellement les règles iptables du système. Utilisez-la avec précaution en environnement de production !