#!/bin/bash

# Script d'installation de l'application de gestion de pare-feux
# Usage: ./setup.sh

set -e

echo "🔥 Firewall Management System - Installation"
echo "=============================================="
echo ""

# Vérifier Python
echo "📦 Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed!"
    echo "Install it with: sudo apt-get install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✅ Python $PYTHON_VERSION found"

# Vérifier iptables
echo ""
echo "🔍 Checking iptables..."
if ! command -v iptables &> /dev/null; then
    echo "⚠️  iptables is not installed!"
    echo "Install it with: sudo apt-get install iptables"
    read -p "Continue without iptables? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "✅ iptables found"
    
    # Vérifier les permissions
    if [ "$EUID" -ne 0 ]; then
        echo "⚠️  Note: You'll need sudo to run the server (for iptables access)"
    fi
fi

# Créer l'arborescence
echo ""
echo "📁 Creating directory structure..."
mkdir -p server
mkdir -p client
mkdir -p common
mkdir -p data/logs
mkdir -p web

echo "✅ Directories created"

# Créer un script de lancement
echo ""
echo "🚀 Creating launch scripts..."

cat > start_server.sh << 'EOF'
#!/bin/bash
echo "Starting Firewall Management Server..."
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Running without root - iptables commands will fail"
    echo "Use: sudo ./start_server.sh for full functionality"
fi
python3 server/server.py
EOF

cat > start_client.sh << 'EOF'
#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: ./start_client.sh <username>"
    echo "Example: ./start_client.sh admin"
    exit 1
fi
python3 client/client.py -H localhost -u $1 -p
EOF

chmod +x start_server.sh start_client.sh

echo "✅ Launch scripts created"

# Créer un fichier de configuration
cat > config.json << 'EOF'
{
  "server": {
    "host": "0.0.0.0",
    "port": 7890,
    "max_clients": 10
  },
  "security": {
    "session_timeout": 3600,
    "max_login_attempts": 5
  },
  "logging": {
    "level": "INFO",
    "directory": "data/logs"
  }
}
EOF

echo "✅ Configuration file created"

# Afficher le résumé
echo ""
echo "✅ Installation complete!"
echo ""
echo "📖 Quick Start Guide:"
echo "===================="
echo ""
echo "1. Start the server:"
echo "   sudo ./start_server.sh"
echo ""
echo "2. In another terminal, start the client:"
echo "   ./start_client.sh admin"
echo "   (default password: admin)"
echo ""
echo "3. Open the web interface:"
echo "   Open web/index.html in your browser"
echo ""
echo "📝 Important Notes:"
echo "==================="
echo "• The server needs root privileges to modify iptables"
echo "• Default admin credentials: admin/admin"
echo "• Change the admin password after first login!"
echo "• Logs are stored in data/logs/"
echo ""
echo "📚 Documentation:"
echo "================="
echo "See README.md for detailed usage instructions"
echo ""
echo "🔥 Ready to manage firewalls!"