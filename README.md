# Lab Red Team / Blue Team — Détection d'Intrusion Réseau

> Simulation d'attaques réseau et détection en temps réel avec Suricata IDS  
> Environnement virtualisé — VirtualBox | Kali Linux | Ubuntu Server | Suricata | Wireshark

---

## Présentation

Ce lab simule un exercice **Red Team / Blue Team** en environnement isolé.  
L'objectif est de comprendre concrètement comment les attaques réseau sont lancées et comment elles sont détectées par un IDS.

|           Rôle          |     Machine    |      IP    |              Outils            |
|-------------------------|----------------|------------|--------------------------------|
|   Attaquant (Red Team)  |    Kali Linux  | 10.0.1.10  |   Nmap · Hydra · curl · ping   |
|          Cible          | Ubuntu Serveur | 10.0.1.20  |       Apache2 · OpenSSH        |
|  Défenseur (Blue Team)  |   Ubuntu IDS   | 10.0.1.30  | Suricata · Wireshark · tcpdump |

---

## Architecture du Lab

```
┌─────────────────────────────────────────────────────────┐
│                      intnet_LAB (isolé)                 │
│                         10.0.1.0/24                     │
│                                                         │
│  ┌──────────────┐    ┌──────────────┐  ┌─────────────┐  │
│  │  Kali Linux  │    │Ubuntu Serveur│  │  Ubuntu IDS │  │
│  │  10.0.1.10   │──▶│  10.0.1.20   │  │   10.0.1.30 │  │
│  │   Red Team   │    │ Apache+SSH   │  │   Suricata  |  │
│  └──────────────┘    └──────────────┘  │   Wireshark │  │
│         │                              │(promiscuous)│  │
│         └─────────────────────────────▶└─────────────┘ │
│                   Tout le trafic surveillé              │
└─────────────────────────────────────────────────────────┘
```

> **Mode promiscuous** activé sur l'interface enp0s3 de l'IDS  
> → Capture de TOUT le trafic du réseau, même non destiné à l'IDS

---

## Configuration

### Prérequis
- VirtualBox 7.x
- ISO Kali Linux 2026.x
- ISO Ubuntu Server 26.04 LTS

### Réseau VirtualBox
Toutes les VMs sont connectées sur un réseau interne **intnet_LAB** :
- Adapter 1 → Internal Network → `intnet_LAB`
- Ubuntu IDS → Adapter 2 → NAT (pour l'accès Internet et l'installation des outils)

### IPs statiques configurées

**Kali Linux :**
```bash
sudo nmcli connection modify eth0 ipv4.addresses 10.0.1.10/24 ipv4.method manual
sudo nmcli connection up eth0
```

**Ubuntu Serveur :**
```yaml
# /etc/netplan/50-cloud-init.yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 10.0.1.20/24
```

**Ubuntu IDS :**
```yaml
# /etc/netplan/50-cloud-init.yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 10.0.1.30/24
    enp0s8:
      dhcp4: yes
```

### Services sur Ubuntu Serveur
```bash
sudo apt install apache2 openssh-server -y
sudo systemctl enable apache2 ssh
sudo systemctl start apache2 ssh
```

### Installation Suricata
```bash
sudo apt update
sudo apt install suricata -y
sudo suricata-update          # télécharge les règles Emerging Threats (~50 000 règles)
sudo ip link set enp0s3 promisc on    # activer le mode promiscuous
```

---

## Règles Suricata Personnalisées

Fichier : `/var/lib/suricata/rules/custom.rules`

```
# Règle 1 — Détection scan SYN (Nmap)
alert tcp any any -> $HOME_NET any (msg:"NMAP SYN Scan detecte"; flags:S; threshold:type threshold, track by_src, count 10, seconds 1; classtype:network-scan; sid:9000001; rev:1;)

# Règle 2 — Tentative connexion SSH
alert tcp any any -> $HOME_NET 22 (msg:"Tentative connexion SSH"; classtype:attempted-admin; sid:9000002; rev:2;)

# Règle 3 — Path Traversal HTTP
alert http any any -> $HOME_NET 80 (msg:"Path Traversal tentative"; content:"../"; http_uri; classtype:web-application-attack; sid:9000003; rev:2;)

# Règle 4 — Ping Sweep ICMP
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Sweep"; itype:8; threshold:type threshold, track by_src, count 5, seconds 2; classtype:network-scan; sid:9000004; rev:1;)
```

Activer les règles dans `/etc/suricata/suricata.yaml` :
```yaml
rule-files:
  - suricata.rules
  - custom.rules
```

---

## Attaques Simulées

### Attaque 1 — Scan de ports Nmap (SYN Scan)

**Objectif :** Découvrir les ports ouverts sur la cible

```bash
# Sur Kali
nmap -sS --min-rate 5000 10.0.1.20
```

**Résultat :**
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

**Détection Suricata :**
```
[**] [1:9000001:1] NMAP SYN Scan detecte [**]
[Classification: Network Scan]
06/09/2026-18:35:01 10.0.1.10:58432 -> 10.0.1.20:80
```

---

### Attaque 2 — Brute Force SSH (Hydra)

**Objectif :** Tester des milliers de mots de passe sur le service SSH

```bash
# Sur Kali — décompresser rockyou.txt d'abord
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Lancer l'attaque
hydra -l felicie -P /usr/share/wordlists/rockyou.txt 10.0.1.20 ssh -t 4
```

**Détection Suricata :**
```
[**] [1:2228000:1] SURICATA SSH invalid banner [**]
06/09/2026-07:44:12 10.0.1.10:57794 -> 10.0.1.20:22
[**] [1:9000002:2] Tentative connexion SSH [**]
06/09/2026-07:44:12 10.0.1.10:57796 -> 10.0.1.20:22
```

---

### Attaque 3 — Path Traversal HTTP

**Objectif :** Accéder à des fichiers système via l'URL du serveur web

```bash
# Sur Kali
curl "http://10.0.1.20/../../etc/passwd"
curl "http://10.0.1.20/?file=../../../etc/shadow"
```

**Détection Suricata :**
```
[**] [1:9000003:2] Path Traversal tentative [**]
[Classification: Web Application Attack]
06/09/2026-09:15:33 10.0.1.10:54821 -> 10.0.1.20:80
```

---

### Attaque 4 — Ping Sweep ICMP

**Objectif :** Découvrir les hôtes actifs sur le réseau

```bash
# Sur Kali
ping -c 20 -i 0.1 10.0.1.20
```

**Détection Suricata :**
```
[**] [1:9000004:1] ICMP Ping Sweep [**]
[Classification: Network Scan]
06/09/2026-09:20:11 10.0.1.10 -> 10.0.1.20
```

---

## Détection — Suricata IDS

### Surveillance en temps réel
```bash
# Sur Ubuntu IDS
sudo tail -f /var/log/suricata/fast.log
```

### Logs détaillés JSON (pour SIEM)
```bash
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool
```

### Démarrer/redémarrer Suricata
```bash
sudo systemctl start suricata
sudo systemctl status suricata
```

---

## Analyse avec Wireshark

Wireshark est installé sur Kali en mode promiscuous sur **eth0**.

### Filtres utilisés

|         Attaque        |              Filtre Wireshark              |
|------------------------|--------------------------------------------|
|      Scan Nmap SYN     | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Réponses ports ouverts | `tcp.flags.syn == 1 && tcp.flags.ack == 1` |
|   Ports fermés (RST)   |            `tcp.flags.rst == 1`            |
|      Trafic HTTP       |                   `http`                   |
|       Pings ICMP       |                   `icmp`                   |
|     Résolution ARP     |                   `arp`                    |
|       Trafic SSH       |               `tcp.port == 22`             |

### Pattern détecté — Scan SYN Nmap
```
Kali (10.0.1.10) → Serveur (10.0.1.20) : SYN [port aléatoire]
Serveur → Kali : SYN-ACK [port ouvert] OU RST [port fermé]
Kali → Serveur : RST [coupe sans finir le handshake]

→ Des centaines de SYN en moins d'1 seconde = scan évident !
```

---

## Résultats

|     Attaque     | Outil | Détecté |                Règle                    |
|-----------------|-------|---------|-----------------------------------------|
|     Scan SYN    |  Nmap |   ok    |         sid:9000001 (custom)            |
| Brute Force SSH | Hydra |   ok    | sid:2228000 (ET) + sid:9000002 (custom) |
| Path Traversal  |  curl |   ok    |         sid:9000003 (custom)            |
|   Ping Sweep    |  ping |   ok    |         sid:9000004 (custom)            |

---

## Concepts Appris

### NIDS vs HIDS
```
Suricata (NIDS) :
→ Surveille le trafic RÉSEAU
→ Détecte avant que l'attaque arrive
→ Aveugle au trafic chiffré (TLS)

Falco (HIDS) :
→ Surveille l'intérieur des machines (kernel)
→ Détecte même le trafic chiffré
→ Complémentaires !
```

### Mode Promiscuous
```
Sans promiscuous : l'IDS voit seulement ses propres paquets
Avec promiscuous : l'IDS voit TOUT le trafic du réseau
→ Obligatoire pour un NIDS efficace
```

### 3-Way Handshake TCP
```
SYN → SYN-ACK → ACK = connexion établie
Scan Nmap SYN : envoie SYN mais jamais le ACK final
→ Discret mais détectable (pattern anormal)
```

---

## Liens avec les Réglementations

| Réglementation | Lien avec ce lab |
|---------------|-----------------|
| **PCI-DSS** Exigence 11 | Tests de pénétration obligatoires |
| **DORA** Pilier 3 | TLPT (Threat-Led Penetration Testing) |
| **NIS2** | Tests de résilience |

---

## Structure du Repo

```
lab-red-blue-team/
├── README.md                    # Ce fichier
├── rules/
│   └── custom.rules             # Règles Suricata personnalisées
├── config/
│   ├── suricata.yaml            # Config Suricata (extraits)
│   └── netplan-ids.yaml         # Config réseau Ubuntu IDS
├── screenshots/
│   ├── fast_log_alerts.png      # Alertes dans fast.log
│   ├── wireshark_syn_scan.png   # Capture scan Nmap
│   ├── wireshark_ssh.png        # Capture brute force SSH
│   └── wireshark_http.png       # Capture path traversal
└── scripts/
    └── setup_ids.sh             # Script d'installation Suricata
```

---

## Auteure

**Félicie Leslie NGUIAMBA MIFOUNGO**  
Cycle Ingénieur Informatique — 3IL Ingénieurs, Limoges  
Spécialité : Réseau & Sécurité  

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Félicie_NGUIAMBA-blue)](https://www.linkedin.com/in/leslie-nguiamba-8846852a0)
[![Email](https://img.shields.io/badge/Email-felicienguiamba@gmail.com-red)](mailto:felicienguiamba@gmail.com)

---

*Lab réalisé en autonomie dans le cadre de la préparation au parcours en Réseau & Sécurité*
