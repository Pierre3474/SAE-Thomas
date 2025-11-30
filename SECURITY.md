# 🔒 Guide de Sécurité

Ce document décrit les fonctionnalités de sécurité implémentées dans l'application de gestion de pare-feux.

## 📋 Table des matières

1. [Authentification Challenge/Réponse](#authentification-challengeréponse)
2. [Chiffrement SSL/TLS](#chiffrement-ssltls)
3. [Support IPv6](#support-ipv6)
4. [Bonnes Pratiques](#bonnes-pratiques)

---

## 🔐 Authentification Challenge/Réponse

### Principe

L'application utilise un mécanisme d'authentification sécurisé en deux étapes pour éviter la transmission du mot de passe en clair :

1. **Étape 1 : Demande de Challenge**
   - Le client envoie le nom d'utilisateur au serveur
   - Le serveur génère un **nonce** aléatoire (challenge) et le renvoie au client

2. **Étape 2 : Réponse au Challenge**
   - Le client calcule : `SHA256(challenge + SHA256(password))`
   - Le client envoie ce hash au serveur
   - Le serveur vérifie en calculant : `SHA256(challenge + password_hash_stocké)`
   - Si les hash correspondent, l'authentification réussit

### Avantages

- ✅ Le mot de passe ne transite **jamais** en clair sur le réseau
- ✅ Protection contre les attaques par **rejeu** (replay attacks) grâce au nonce unique
- ✅ Protection contre les **timing attacks** avec `secrets.compare_digest()`
- ✅ Utilisation de **SHA-256** pour le hashage

### Code Implémentation

**Côté Serveur (server.py):**
```python
# Génération du challenge
challenge = secrets.token_hex(32)
self.auth_challenges[username] = challenge

# Vérification
expected_hash = hashlib.sha256(
    (challenge + user.password_hash).encode('utf-8')
).hexdigest()

if secrets.compare_digest(response_hash, expected_hash):
    # Authentification réussie
```

**Côté Client (client.py):**
```python
# Hash du mot de passe
password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

# Réponse au challenge
response_hash = hashlib.sha256(
    (challenge + password_hash).encode('utf-8')
).hexdigest()
```

---

## 🔒 Chiffrement SSL/TLS

### Configuration

L'application supporte le chiffrement SSL/TLS pour sécuriser toutes les communications entre le client et le serveur.

### Génération des Certificats Auto-Signés

#### Méthode 1 : Script Automatique (Recommandé)

```bash
# Exécuter le script de génération
./generate_ssl_certs.sh
```

Le script vous guidera à travers la configuration et générera :
- `server/certs/server.crt` : Le certificat SSL
- `server/certs/server.key` : La clé privée

#### Méthode 2 : Commande Manuelle

```bash
# Créer le répertoire
mkdir -p server/certs

# Générer le certificat et la clé (valide 365 jours)
openssl req -x509 \
    -newkey rsa:4096 \
    -nodes \
    -sha256 \
    -days 365 \
    -keyout server/certs/server.key \
    -out server/certs/server.crt \
    -subj "/C=FR/ST=France/L=Paris/O=SAE 3.02/CN=localhost"
```

**Paramètres personnalisables :**
- `-days 365` : Durée de validité (modifiable)
- `CN=localhost` : Remplacer par votre IP ou nom de domaine
- `-newkey rsa:4096` : Clé RSA de 4096 bits (très sécurisé)

### Utilisation

**Démarrage du Serveur avec SSL (par défaut) :**
```bash
sudo python3 server/server.py
```

**Connexion du Client avec SSL (par défaut) :**
```bash
python3 client/client.py -H localhost -u admin -p
```

**Désactiver SSL (non recommandé) :**
```bash
# Serveur
python3 server/server.py  # Modifier use_ssl=False dans le code

# Client
python3 client/client.py -H localhost -u admin -p --no-ssl
```

### Paramètres de Sécurité

L'implémentation SSL/TLS utilise les paramètres de sécurité suivants :

**Serveur :**
```python
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
ssl_context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')
```

**Client :**
```python
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
ssl_context.check_hostname = False  # Pour certificats auto-signés
ssl_context.verify_mode = ssl.CERT_NONE  # Pour certificats auto-signés
```

### Vérification du Certificat

Pour afficher les informations du certificat généré :
```bash
openssl x509 -in server/certs/server.crt -text -noout
```

---

## 🌐 Support IPv6

L'application supporte **automatiquement** IPv4 et IPv6 grâce à l'utilisation de `socket.getaddrinfo()`.

### Serveur

Le serveur peut écouter sur :
- **IPv4** : `0.0.0.0:7890`
- **IPv6** : `[::]:7890` (mode dual-stack acceptant aussi IPv4)

**Mode Dual-Stack :**
```python
# Écoute sur IPv6 ET IPv4 en même temps
raw_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
```

### Client

Le client détecte automatiquement le type d'adresse :

```bash
# IPv4
python3 client/client.py -H 192.168.1.100 -u admin -p

# IPv6
python3 client/client.py -H "::1" -u admin -p
python3 client/client.py -H "2001:db8::1" -u admin -p

# Nom de domaine (résolu en IPv4 ou IPv6)
python3 client/client.py -H localhost -u admin -p
```

### Avantages

- ✅ Compatibilité automatique IPv4/IPv6
- ✅ Pas de configuration supplémentaire nécessaire
- ✅ Utilisation de `getaddrinfo()` pour une résolution correcte
- ✅ Mode dual-stack sur le serveur

---

## 🛡️ Bonnes Pratiques

### 1. Gestion des Mots de Passe

**À FAIRE :**
- ✅ Changer le mot de passe admin par défaut (`admin/admin`)
- ✅ Utiliser des mots de passe forts (min. 12 caractères, mix majuscules/minuscules/chiffres/symboles)
- ✅ Les mots de passe sont hashés avec SHA-256 avant stockage

**NE PAS FAIRE :**
- ❌ Utiliser le compte admin par défaut en production
- ❌ Partager les identifiants
- ❌ Réutiliser des mots de passe

**Exemple de création d'un utilisateur sécurisé :**
```bash
fwcli> users create bob "M0tDeP@sseF0rt!2024" editor
```

### 2. Certificats SSL

**Pour la SAE / Développement :**
- ✅ Certificats auto-signés générés avec le script fourni
- ✅ Validité de 365 jours

**Pour la Production :**
- ✅ Utiliser des certificats signés par une CA reconnue (Let's Encrypt, DigiCert, etc.)
- ✅ Activer la vérification du certificat côté client (`--verify-cert`)
- ✅ Renouveler les certificats avant expiration

### 3. Permissions et Rôles

L'application implémente 3 niveaux de rôles :

| Rôle | Permissions |
|------|-------------|
| **admin** | Gestion complète (users, firewalls, tous pare-feux) |
| **editor** | Gestion des pare-feux assignés (lecture/écriture) |
| **reader** | Lecture seule des pare-feux assignés |

**Principe du moindre privilège :**
```bash
# Créer un utilisateur avec accès limité
fwcli> users create alice "SecureP@ss123" editor
```

### 4. Journalisation

Tous les événements importants sont journalisés :
- ✅ Authentifications réussies/échouées
- ✅ Commandes exécutées
- ✅ Modifications des pare-feux
- ✅ Erreurs système

**Emplacement des logs :**
```
data/logs/firewall_YYYY-MM-DD.log
```

**Exemple de log :**
```
[2024-01-15T10:23:45] [INFO] [admin@192.168.1.10] Authentication successful
[2024-01-15T10:24:12] [CMD] [admin@srv1] fw start srv1
[2024-01-15T10:25:30] [ERROR] [bob] Permission denied: users list
```

### 5. Réseau et Pare-feu

**Recommandations :**
- ✅ Exécuter le serveur avec `sudo` (requis pour iptables)
- ✅ Restreindre l'accès au port 7890 avec un pare-feu
- ✅ Utiliser un VPN pour l'accès distant
- ✅ Surveiller les tentatives de connexion échouées

**Exemple de restriction iptables sur le serveur :**
```bash
# Autoriser seulement le réseau local
sudo iptables -A INPUT -p tcp --dport 7890 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 7890 -j DROP
```

### 6. Maintenance

**Sauvegardes régulières :**
```bash
# Sauvegarder les données
cp -r data/ data_backup_$(date +%Y%m%d)/

# Sauvegarder les logs
tar -czf logs_backup_$(date +%Y%m%d).tar.gz data/logs/
```

**Rotation des logs :**
```bash
# Script de rotation (à ajouter à cron)
find data/logs/ -name "*.log" -mtime +30 -delete
```

---

## 🔍 Tests de Sécurité

### Tester l'Authentification Challenge/Réponse

```bash
# Connexion normale
python3 client/client.py -H localhost -u admin -p
# Entrer le mot de passe
# Observer les messages de challenge dans les logs
```

### Tester SSL/TLS

```bash
# Vérifier que SSL est actif
openssl s_client -connect localhost:7890

# Observer le certificat et la version TLS utilisée
```

### Tester IPv6

```bash
# Serveur écoute sur IPv6
netstat -tunlp | grep 7890

# Connexion IPv6
python3 client/client.py -H "::1" -u admin -p
```

---

## 📚 Références

- **OWASP Top 10** : https://owasp.org/www-project-top-ten/
- **TLS Best Practices** : https://wiki.mozilla.org/Security/Server_Side_TLS
- **Python SSL Documentation** : https://docs.python.org/3/library/ssl.html
- **RFC 5246 (TLS 1.2)** : https://tools.ietf.org/html/rfc5246

---

## ⚠️ Avertissements

1. **Certificats Auto-Signés** : Ne pas utiliser en production réelle
2. **Exécution Root** : Le serveur nécessite sudo pour iptables (risque de sécurité)
3. **SAE 3.02** : Ce projet est conçu pour un environnement éducatif
4. **Tests Uniquement** : Ne pas déployer sur Internet sans audit de sécurité complet

---

**Date de dernière mise à jour** : Novembre 2025
**Version** : 1.0 - SAE 3.02
