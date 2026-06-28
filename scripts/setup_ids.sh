#!/bin/bash
# setup_ids.sh — Installation et configuration Suricata sur Ubuntu IDS
# Auteure : Félicie NGUIAMBA MIFOUNGO

echo " Installation Suricata IDS "

# Mise à jour système
sudo apt update && sudo apt upgrade -y

# Installation Suricata
sudo apt install suricata -y

# Téléchargement des règles Emerging Threats
sudo suricata-update

# Mode promiscuous sur l'interface réseau
sudo ip link set enp0s3 promisc on

# Copie des règles personnalisées
sudo cp custom.rules /var/lib/suricata/rules/custom.rules

# Redémarrage Suricata
sudo systemctl restart suricata
sudo systemctl enable suricata

echo " Vérification "
sudo systemctl status suricata
echo ""
echo "Suricata installé et configuré "
echo "Logs disponibles dans /var/log/suricata/"
echo "  → fast.log  : alertes simples"
echo "  → eve.json  : logs JSON complets"
echo ""
echo "Surveiller les alertes en temps réel :"
echo "  sudo tail -f /var/log/suricata/fast.log"
