# 🚀 Guide de Déploiement

Guide complet pour déployer l'application de gestion de pare-feux en production.

## 📋 Table des Matières

1. [Prérequis](#prérequis)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Lancement des Services](#lancement-des-services)
5. [Sécurité](#sécurité)
6. [Monitoring](#monitoring)
7. [Maintenance](#maintenance)

## Prérequis

### Système d'exploitation
- Linux (Ubuntu 20.04+, Debian 10+, CentOS 8+)
- Python 3.8 ou supérieur
- iptables installé et configuré
- Droits root pour manipuler iptables

### Ressources recommandées
- CPU: 2 cores minimum
- RAM: 2GB minimum
- Disque: 10GB minimum
- Réseau: Port 7890 (TCP) et 8080 (HTTP) ouverts

### Installation des dépendances système

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y python3 python3-pip iptables iptables-persistent

# CentOS/RHEL
sudo yum install -y python3 python3-pip iptables iptables-services
```

## Installation

### 1. Cloner le projet

```bash
cd /opt
sudo git clone <repository-url> firewall-manager
cd firewall-manager
```

### 2. Configuration des permissions

```bash
# Créer un utilisateur dédié
sudo useradd -r -s /bin/bash -d /opt/firewall-manager firewall

# Donner les permissions
sudo chown -R firewall:firewall /opt/firewall-manager

# Permissions sudo pour iptables
echo "firewall ALL=(ALL) NOPASSWD: /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore" | sudo tee /etc/sudoers.d/firewall
```

### 3. Structure des répertoires

```bash
sudo -u firewall mkdir -p /opt/firewall-manager/{data/logs,server,client,common,web}
```

## Configuration

### 1. Fichier de configuration principal

Créer `/opt/firewall-manager/config.json` :

```json
{
  "server": {
    "tcp_host": "0.0.0.0",
    "tcp_port": 7890,
    "http_host": "0.0.0.0",
    "http_port": 8080,
    "max_clients": 50
  },
  "security": {
    "session_timeout": 3600,
    "max_login_attempts": 5,
    "enable_tls": false,
    "cert_file": "/opt/firewall-manager/certs/server.crt",
    "key_file": "/opt/firewall-manager/certs/server.key"
  },
  "logging": {
    "level": "INFO",
    "directory": "/opt/firewall-manager/data/logs",
    "max_size_mb": 100,
    "backup_count": 30
  },
  "database": {
    "directory": "/opt/firewall-manager/data"
  }
}
```

### 2. Changer le mot de passe admin

```bash
# Se connecter et changer le mot de passe
python3 client/client.py -H localhost -u admin -p
# password: admin
fwcli> users passwd <nouveau_mot_de_passe_fort>
```

## Lancement des Services

### 1. Service systemd pour le serveur TCP

Créer `/etc/systemd/system/firewall-tcp.service` :

```ini
[Unit]
Description=Firewall Management TCP Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/firewall-manager
ExecStart=/usr/bin/python3 /opt/firewall-manager/server/server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 2. Service systemd pour le serveur Web

Créer `/etc/systemd/system/firewall-web.service` :

```ini
[Unit]
Description=Firewall Management Web Server
After=network.target

[Service]
Type=simple
User=firewall
WorkingDirectory=/opt/firewall-manager
ExecStart=/usr/bin/python3 /opt/firewall-manager/server/webserver.py -p 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 3. Activer et démarrer les services

```bash
# Recharger systemd
sudo systemctl daemon-reload

# Activer les services au démarrage
sudo systemctl enable firewall-tcp
sudo systemctl enable firewall-web

# Démarrer les services
sudo systemctl start firewall-tcp
sudo systemctl start firewall-web

# Vérifier le statut
sudo systemctl status firewall-tcp
sudo systemctl status firewall-web
```

### 4. Vérification

```bash
# Tester le serveur TCP
telnet localhost 7890

# Tester le serveur Web
curl http://localhost:8080

# Voir les logs
sudo journalctl -u firewall-tcp -f
sudo journalctl -u firewall-web -f
```

## Sécurité

### 1. Firewall système

```bash
# Ouvrir les ports nécessaires
sudo ufw allow 7890/tcp comment "Firewall Management TCP"
sudo ufw allow 8080/tcp comment "Firewall Management Web"

# Ou avec iptables
sudo iptables -A INPUT -p tcp --dport 7890 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

### 2. Nginx en reverse proxy (recommandé pour production)

Installer nginx :
```bash
sudo apt-get install -y nginx
```

Configuration `/etc/nginx/sites-available/firewall-manager` :

```nginx
server {
    listen 80;
    server_name firewall.example.com;

    # Redirection HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name firewall.example.com;

    ssl_certificate /etc/letsencrypt/live/firewall.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/firewall.example.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Activer :
```bash
sudo ln -s /etc/nginx/sites-available/firewall-manager /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 3. Certificats SSL avec Let's Encrypt

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d firewall.example.com
```

### 4. Limiter l'accès par IP

Dans nginx, ajouter :
```nginx
location / {
    # Autoriser seulement certaines IPs
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;
    
    proxy_pass http://127.0.0.1:8080;
}
```

## Monitoring

### 1. Logs applicatifs

```bash
# Logs en temps réel
tail -f /opt/firewall-manager/data/logs/firewall_$(date +%Y-%m-%d).log

# Recherche dans les logs
grep "ERROR" /opt/firewall-manager/data/logs/firewall_*.log
grep "alice" /opt/firewall-manager/data/logs/firewall_*.log
```

### 2. Monitoring système

Script de monitoring `/opt/firewall-manager/monitor.sh` :

```bash
#!/bin/bash

echo "=== Firewall Manager Status ==="
echo ""

# Services
echo "Services:"
systemctl is-active --quiet firewall-tcp && echo "  ✅ TCP Server: Running" || echo "  ❌ TCP Server: Stopped"
systemctl is-active --quiet firewall-web && echo "  ✅ Web Server: Running" || echo "  ❌ Web Server: Stopped"

# Ports
echo ""
echo "Ports:"
netstat -ln | grep ":7890 " > /dev/null && echo "  ✅ Port 7890: Listening" || echo "  ❌ Port 7890: Not listening"
netstat -ln | grep ":8080 " > /dev/null && echo "  ✅ Port 8080: Listening" || echo "  ❌ Port 8080: Not listening"

# Disk usage
echo ""
echo "Disk Usage:"
du -sh /opt/firewall-manager/data/logs/

# Recent errors
echo ""
echo "Recent Errors (last 10):"
grep "ERROR" /opt/firewall-manager/data/logs/firewall_$(date +%Y-%m-%d).log | tail -10
```

Rendre exécutable :
```bash
chmod +x /opt/firewall-manager/monitor.sh
```

### 3. Alertes avec cron

Créer un script d'alerte `/opt/firewall-manager/alert.sh` :

```bash
#!/bin/bash

if ! systemctl is-active --quiet firewall-tcp; then
    echo "ALERT: TCP Server is down!" | mail -s "Firewall Manager Alert" admin@example.com
fi

if ! systemctl is-active --quiet firewall-web; then
    echo "ALERT: Web Server is down!" | mail -s "Firewall Manager Alert" admin@example.com
fi
```

Ajouter au crontab :
```bash
# Vérification toutes les 5 minutes
*/5 * * * * /opt/firewall-manager/alert.sh
```

## Maintenance

### 1. Backup automatique

Script de backup `/opt/firewall-manager/backup.sh` :

```bash
#!/bin/bash

BACKUP_DIR="/backup/firewall-manager"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup des données
tar -czf $BACKUP_DIR/firewall_data_$DATE.tar.gz \
    /opt/firewall-manager/data/users.json \
    /opt/firewall-manager/data/firewalls.json

# Backup des logs (derniers 7 jours)
tar -czf $BACKUP_DIR/firewall_logs_$DATE.tar.gz \
    /opt/firewall-manager/data/logs/firewall_$(date +%Y-%m-%d --date="7 days ago" | cut -d'-' -f1-2)*.log

# Nettoyer les backups de plus de 30 jours
find $BACKUP_DIR -name "firewall_*.tar.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

Crontab quotidien :
```bash
0 2 * * * /opt/firewall-manager/backup.sh
```

### 2. Rotation des logs

Créer `/etc/logrotate.d/firewall-manager` :

```
/opt/firewall-manager/data/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 firewall firewall
}
```

### 3. Mise à jour

```bash
cd /opt/firewall-manager
sudo git pull
sudo systemctl restart firewall-tcp firewall-web
```

### 4. Nettoyage

```bash
# Supprimer les anciennes sessions
# (À implémenter dans l'application)

# Nettoyer les logs de plus de 90 jours
find /opt/firewall-manager/data/logs -name "*.log" -mtime +90 -delete
```

## Troubleshooting

### Le serveur ne démarre pas

```bash
# Vérifier les logs
sudo journalctl -u firewall-tcp -n 50

# Vérifier les permissions
ls -la /opt/firewall-manager

# Vérifier le port
netstat -ln | grep 7890
```

### Problèmes d'accès iptables

```bash
# Vérifier sudo
sudo -u root iptables -L

# Vérifier les permissions sudoers
cat /etc/sudoers.d/firewall
```

### Logs qui ne s'écrivent pas

```bash
# Vérifier les permissions du répertoire
ls -la /opt/firewall-manager/data/logs/

# Créer manuellement si nécessaire
mkdir -p /opt/firewall-manager/data/logs
chown firewall:firewall /opt/firewall-manager/data/logs
```

## Checklist de Production

- [ ] Changer le mot de passe admin par défaut
- [ ] Configurer le firewall système (ufw/iptables)
- [ ] Installer et configurer nginx en reverse proxy
- [ ] Activer HTTPS avec certificats SSL
- [ ] Restreindre l'accès par IP si nécessaire
- [ ] Configurer les backups automatiques
- [ ] Configurer la rotation des logs
- [ ] Mettre en place le monitoring
- [ ] Configurer les alertes email
- [ ] Tester le disaster recovery
- [ ] Documenter les procédures opérationnelles

## Support

Pour toute question ou problème :
- Consulter les logs : `/opt/firewall-manager/data/logs/`
- Vérifier le statut : `sudo systemctl status firewall-tcp firewall-web`
- Documentation complète : `README.md`
