#!/bin/bash
################################################################################
# Script de génération de certificats SSL auto-signés
# Pour l'application de gestion de pare-feux
################################################################################

set -e

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                           ║${NC}"
echo -e "${BLUE}║     🔒 GÉNÉRATEUR DE CERTIFICATS SSL AUTO-SIGNÉS         ║${NC}"
echo -e "${BLUE}║                                                           ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Répertoire de destination
CERT_DIR="server/certs"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"

# Créer le répertoire s'il n'existe pas
echo -e "${YELLOW}📁 Création du répertoire de certificats...${NC}"
mkdir -p "$CERT_DIR"

# Vérifier si openssl est installé
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}❌ Erreur: openssl n'est pas installé${NC}"
    echo -e "${YELLOW}💡 Installez openssl avec:${NC}"
    echo -e "   Ubuntu/Debian: sudo apt-get install openssl"
    echo -e "   CentOS/RHEL:   sudo yum install openssl"
    echo -e "   macOS:         brew install openssl"
    exit 1
fi

# Vérifier si les certificats existent déjà
if [ -f "$CERT_FILE" ] || [ -f "$KEY_FILE" ]; then
    echo -e "${YELLOW}⚠️  Des certificats existent déjà dans $CERT_DIR${NC}"
    read -p "Voulez-vous les remplacer? (o/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
        echo -e "${BLUE}ℹ️  Génération annulée${NC}"
        exit 0
    fi
    echo -e "${YELLOW}🗑️  Suppression des anciens certificats...${NC}"
    rm -f "$CERT_FILE" "$KEY_FILE"
fi

# Paramètres par défaut
DEFAULT_COUNTRY="FR"
DEFAULT_STATE="France"
DEFAULT_CITY="Paris"
DEFAULT_ORG="SAE 3.02"
DEFAULT_CN="localhost"
DEFAULT_DAYS="365"

echo -e "${GREEN}📝 Configuration du certificat${NC}"
echo -e "${BLUE}(Appuyez sur Entrée pour utiliser les valeurs par défaut)${NC}"
echo ""

# Demander les informations pour le certificat
read -p "Pays (Code à 2 lettres) [$DEFAULT_COUNTRY]: " COUNTRY
COUNTRY=${COUNTRY:-$DEFAULT_COUNTRY}

read -p "État/Province [$DEFAULT_STATE]: " STATE
STATE=${STATE:-$DEFAULT_STATE}

read -p "Ville [$DEFAULT_CITY]: " CITY
CITY=${CITY:-$DEFAULT_CITY}

read -p "Organisation [$DEFAULT_ORG]: " ORG
ORG=${ORG:-$DEFAULT_ORG}

read -p "Nom commun (CN) - IP ou domaine [$DEFAULT_CN]: " CN
CN=${CN:-$DEFAULT_CN}

read -p "Durée de validité (jours) [$DEFAULT_DAYS]: " DAYS
DAYS=${DAYS:-$DEFAULT_DAYS}

echo ""
echo -e "${YELLOW}🔑 Génération du certificat et de la clé privée...${NC}"
echo ""

# Générer le certificat auto-signé et la clé privée
# -x509 : certificat auto-signé
# -newkey rsa:4096 : nouvelle clé RSA de 4096 bits
# -nodes : pas de chiffrement de la clé privée (pas de passphrase)
# -sha256 : utiliser SHA-256 pour la signature
# -days : durée de validité
openssl req -x509 \
    -newkey rsa:4096 \
    -nodes \
    -sha256 \
    -days "$DAYS" \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$CN"

# Définir les permissions appropriées
chmod 600 "$KEY_FILE"  # Clé privée : lecture/écriture propriétaire seulement
chmod 644 "$CERT_FILE" # Certificat : lecture pour tous

echo ""
echo -e "${GREEN}✅ Certificats générés avec succès!${NC}"
echo ""
echo -e "${BLUE}📄 Informations du certificat:${NC}"
echo -e "   Certificat : ${GREEN}$CERT_FILE${NC}"
echo -e "   Clé privée : ${GREEN}$KEY_FILE${NC}"
echo -e "   Validité   : ${GREEN}$DAYS jours${NC}"
echo -e "   CN         : ${GREEN}$CN${NC}"
echo ""

# Afficher les détails du certificat
echo -e "${BLUE}🔍 Détails du certificat généré:${NC}"
openssl x509 -in "$CERT_FILE" -text -noout | grep -A 2 "Subject:\|Validity" | head -n 6

echo ""
echo -e "${GREEN}🎉 Configuration terminée!${NC}"
echo ""
echo -e "${YELLOW}💡 Prochaines étapes:${NC}"
echo -e "   1. Démarrez le serveur: ${GREEN}sudo python3 server/server.py${NC}"
echo -e "   2. Le serveur utilisera automatiquement le chiffrement SSL/TLS"
echo -e "   3. Connectez-vous avec le client: ${GREEN}python3 client/client.py -H localhost -u admin -p${NC}"
echo ""
echo -e "${YELLOW}⚠️  Note importante:${NC}"
echo -e "   Ce certificat est AUTO-SIGNÉ et ne doit être utilisé que pour:"
echo -e "   - Développement et tests"
echo -e "   - Environnements de formation (SAE)"
echo -e "   - Réseaux internes sécurisés"
echo ""
echo -e "   Pour la production, utilisez un certificat signé par une CA reconnue!"
echo ""
