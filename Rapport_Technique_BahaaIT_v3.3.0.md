# Rapport Technique & Fonctionnel — BahaaIT Network Tools (v3.3.0)

> Ce document présente l'architecture logicielle, la pile technologique, la couverture fonctionnelle, les mécanismes de sécurité ainsi que le pipeline de déploiement de l'application **BahaaIT Network Tools v3.3.0**. Il est conçu pour servir de support d'analyse technique ou d'audit fonctionnel.

---

## 1. Vue d'Ensemble & Objectif du Projet

**BahaaIT Network Tools** est une suite logicielle tout-en-un d'administration, de supervision et de diagnostic réseau pour **Windows 10 / 11 (64-bit)**, pensée pour les administrateurs systèmes et réseaux, techniciens IT sur site et ingénieurs support.

### Problématique adressée
Lors d'interventions réseau (audit de bornes Wi-Fi Ruckus, configuration de switches/routeurs, diagnostic de coupures WAN/DNS, supervision de parc multi-sites), les techniciens doivent habituellement jongler entre une dizaine d'outils disparates (`cmd`, Putty, Angry IP Scanner, navigateur web bloqué par les certificats SSL auto-signés, utilitaires Wi-Fi, fichiers Excel d'inventaire).  
**BahaaIT Network Tools** centralise l'ensemble de ces opérations dans une interface unique, moderne (**Quantum Midnight UI**), bilingue (**Français / Anglais**) et autonome.

---

## 2. Architecture Logicielle & Stack Technologique

### Pile Technologique (Tech Stack)

| Domaine | Technologie / Bibliothèque | Rôle dans l'application |
| :--- | :--- | :--- |
| **Langage & Runtime** | Python 3.14 (64-bit) | Exécution principale, typage et concurrence (`asyncio`, `ThreadPoolExecutor`) |
| **Interface Graphique** | `PySide6` (Qt 6) & `PySide6-WebEngine` | Interface desktop native, graphiques temps réel `QPainter`, navigateur Chromium intégré |
| **Base de Données** | `SQLite` + `SQLAlchemy 2.0` | Stockage local relationnel (`network_tools.db`) : hôtes supervisés, logs de ping, historique Speedtest, services globaux |
| **Moteurs Réseau** | `scapy` (Npcap), `icmplib`, `psutil`, `asyncio`, `netsh` | Découverte ARP/ICMP, scan de ports asynchrone haute vitesse, télémétrie cartes réseau, analyse Wi-Fi BSSID |
| **Administration Distante** | `paramiko`, `mstsc` (RDP) | Client terminal SSH intégré multi-sessions et lancement de sessions Bureau à distance |
| **Authentification & Sécurité** | `supabase`, `gotrue`, Windows `Crypt32.dll` (DPAPI) | Authentification utilisateur cloud et chiffrement matériel local lié au profil Windows |
| **Reporting & Export** | `reportlab`, `QPrinter`, `csv`, `json` | Génération de rapports PDF professionnels (Speedtest, Inventaire Sites), exports CSV/TXT/JSON |
| **Packaging & Distribution** | `PyInstaller`, `Inno Setup`, GitHub Releases | Compilation `--onedir`, installateur Windows `.exe` avec élévation UAC Admin et mise à jour OTA |

---

## 3. Cartographie Fonctionnelle Détaillée (11 Modules)

### 3.1. Tableau de Bord (`Dashboard`)
- **Graphique de débit temps réel** (`src/ui/widgets/bandwidth_chart.py`) : Courbes fluides Download / Upload calculées via les compteurs d'octets système (`psutil.net_io_counters`) avec mise à l'échelle dynamique (`KB/s`, `MB/s`).
- **En-tête global permanent** (`src/ui/main_window.py`) : Affiche en permanence le `Hostname`, l'`IP Locale`, l'`IP Publique` et l'état de la liaison active (`Wi-Fi` avec SSID et puissance du signal en `%`, ou `Ethernet`).

### 3.2. Supervision Continue (`Live Monitoring / Ping Monitor`)
- **Surveillance multi-hôtes** (`src/ui/widgets/monitor_view.py`, `src/core/monitor.py`) : Ping périodique en arrière-plan d'une liste d'équipements critiques avec mise en pause individuelle persistée en base SQLite.
- **Calcul de disponibilité (SLA / Uptime)** : Calcul du taux de disponibilité (`% Uptime`) et de la latence moyenne sur 30 jours glissants, avec purge automatique des journaux de plus de 30 jours.
- **Système d'alertes double canal** :
  - **Alarme sonore** (`.wav` par défaut ou personnalisé) dès qu'un équipement tombe (`DOWN`).
  - **Alerte Email SMTP** (`src/utils/email_notifier.py`) : Envoi automatique d'un email d'alerte après N échecs consécutifs configurables, et notification de retour à la normale (`UP`).

### 3.3. État des Services Cloud (`Global Status`)
- **Moniteur de services mondiaux** (`src/ui/widgets/global_status_view.py`) : Vérifie la disponibilité et la latence HTTP/ICMP de grands fournisseurs (Google, Cloudflare, AWS, GitHub, Microsoft 365, OpenAI, etc.) avec possibilité d'ajouter des services Web/API personnalisés.

### 3.4. Scanners Réseau & Diagnostic (`Network Scanners` — 5 Modes)
Implémenté dans `src/core/scanner.py` et `src/ui/widgets/scanner_view.py` :
1. **Scan LAN intelligent** :
   - Pour les sous-réseaux `/24` : requête ARP broadcast via `Scapy` (si `Npcap` est présent) avec bascule automatique sur un scan ICMP multithreadé (30 workers) + lecture ARP.
   - Pour les grands réseaux (`/16` ou plus) : lecture instantanée et filtrage de la table ARP système + résolution DNS inverse asynchrone (évite de balayer 65 534 hôtes un par un).
2. **Scan de Ports TCP asynchrone** :
   - Utilise `asyncio` avec un sémaphore de `200` connexions simultanées.
   - Deux modes : *Ports courants* (19 ports standards : FTP, SSH, Telnet, SMTP, DNS, HTTP, HTTPS, SMB, RDP, MySQL, VNC...) ou *Plage personnalisée* (`1–65535`).
3. **Traceroute Temps Réel** :
   - Exécute `tracert -d -w 2000` en streaming ligne par ligne et affiche chaque saut (`Hop #`, `IP`, `RTT1`, `RTT2`, `RTT3`, `État`) en direct avec support des sorties Windows françaises et anglaises.
4. **Scanner Wi-Fi (SSID / BSSID / Canaux / Signal)** :
   - Analyse complète des bornes Wi-Fi environnantes via `netsh wlan show networks mode=bssid` (décodage adaptatif UTF-8 / CP850, support Windows 10/11 FR & EN).
   - Détaille chaque point d'accès physique (**BSSID / MAC Borne**) même lorsqu'ils diffusent le même SSID (indispensable pour auditer des flottes multi-bornes **Ruckus**), avec tri par puissance de signal (`%`), canal et bande (`2.4 GHz`, `5 GHz`, `6 GHz`), norme radio (`802.11ax`, `802.11ac`...) et chiffrement.
5. **Diagnostic Automatique en 1 Clic (`Smart Diagnostic`)** :
   - Exécute séquentiellement 5 contrôles pour isoler instantanément l'origine d'une panne :
     1. *Carte Réseau Locale* (vérification de l'interface active et de la validité de l'IP locale hors loopback/APIPA).
     2. *Passerelle Locale* (détection automatique de la passerelle par défaut et test de ping ICMP).
     3. *Connectivité Internet WAN* (test de routage IP sortant vers `8.8.8.8` avec bascule sur `1.1.1.1`).
     4. *Résolution DNS* (résolution d'un nom de domaine avec mesure du temps de réponse en `ms`).
     5. *Verdict Global* (synthèse intelligente indiquant précisément le maillon défaillant : câble/Wi-Fi, routeur/VLAN, lien FAI WAN, ou serveur DNS).

### 3.5. Boîte à Outils Système (`IT Toolbox`)
Implémentée dans `src/ui/widgets/tools_view.py` et `src/core/tools.py` :
- **Ping continu / paramétrable**, **NSLookup**, **Whois**, **Netstat** (connexions actives).
- **Calculateur de sous-réseau IP** (CIDR, masque, plage d'hôtes, broadcast).
- **Wake-on-LAN (WoL)** (envoi de Magic Packet UDP sur le réseau local).
- **MAC OUI Lookup** (identification du constructeur matériel à partir d'une adresse MAC).
- **Actions rapides de réparation réseau** : *Flush DNS Cache* (`ipconfig /flushdns`) et *Reset Winsock* (`netsh winsock reset`).

### 3.6. Test de Performance (`Speedtest`)
- **Moteur de test de débit** (`src/core/speedtest.py`, `src/ui/widgets/speedtest_view.py`) : Mesure le **Download (Mbps)**, l'**Upload (Mbps)**, le **Ping (ms)**, le **Jitter (ms)** et la **Perte de paquets (%)** avec jauges circulaires animées et courbe temps réel.
- **Sélection de serveurs** : Détection automatique du meilleur serveur proche + catalogue de serveurs internationaux de référence (Paris, Londres, Francfort, New York, Tokyo...).
- **Historique & Export PDF** : Sauvegarde automatique des 100 derniers tests en base SQLite et génération d'un rapport PDF mis en page via `ReportLab` (`src/utils/pdf_generator.py`).

### 3.7. Navigateur d'Administration (`Web Manager`)
- **Navigateur multi-onglets intégré** (`src/ui/widgets/browser_view.py`) basé sur `QWebEngineView` (Chromium).
- **Tolérance SSL/TLS activée par défaut** (`--ignore-certificate-errors`) : Permet d'accéder sans blocage aux interfaces d'administration HTTPS des équipements réseau (contrôleurs Wi-Fi Ruckus, pare-feux Fortinet, switches administrables) utilisant des certificats auto-signés.

### 3.8. Terminal Distant (`Remote Terminal`)
- **Client SSH intégré** (`src/ui/widgets/remote_view.py`) : Connexion SSH interactive via `Paramiko` directement dans l'application, avec gestion de profils enregistrés et lanceur rapide vers le client Bureau à distance Windows (`mstsc.exe` / RDP).

### 3.9. Gestionnaire de Parc Multi-Sites (`Sites Manager`)
- **Inventaire par site** (`src/ui/widgets/sites_view.py`) : Permet de référencer tous les équipements réseau (Nom, Adresse IP/URL, Site) avec liste déroulante éditable et auto-complétion des sites existants.
- **Actions en 1 clic** :
  - *Ping All* ou *Ping unitaire* asynchrone (affiche la latence en `ms` ou l'état `DOWN`).
  - *Ouverture directe dans Web Manager* pour administrer l'équipement.
  - *Import CSV* en masse et *Export PDF* de l'inventaire.

### 3.10. Configuration Réseau (`Network Config / IP Config`)
- **Gestionnaire d'interfaces IPv4** (`src/ui/widgets/net_config_view.py`, `src/core/net_config.py`) :
  - Lecture fiable de l'IP, du masque, de la passerelle par défaut et des serveurs DNS primaire/secondaire (compatible Windows 10/11 FR & EN).
  - Application en 1 clic d'une configuration **IP Statique** ou retour en **DHCP**, avec système de **profils IP pré-enregistrés** (très utile pour basculer rapidement entre le sous-réseau d'un client et le DHCP).

### 3.11. Paramètres, Sauvegarde & Mise à Jour (`App Settings`)
- **Personnalisation & Mode Fantôme** (`src/ui/widgets/settings_view.py`) : Changement de langue FR/EN sans redémarrage, réduction dans la barre des tâches système (*System Tray / Ghost Mode*), lancement automatique au démarrage de Windows (`HKEY_CURRENT_USER\...\Run`).
- **Sauvegarde & Restauration complète** : Export et import de toute la configuration et des hôtes supervisés dans un fichier `.json` unique (avec chiffrement du mot de passe SMTP).
- **Mise à jour automatique (OTA)** (`src/utils/updater.py`) : Vérifie les nouvelles versions sur GitHub Releases, affiche les notes de version, télécharge l'installateur `.exe` avec barre de progression et lance la mise à jour automatiquement.

---

## 4. Sécurité, Fiabilité & Qualité Logicielle

1. **Protection des secrets locaux par Windows DPAPI (64-bit)** (`src/utils/auth.py`, `src/utils/config.py`) :
   - Les jetons de session Supabase (`session.dat`) ainsi que les mots de passe SMTP personnalisés dans `config.json` et dans les fichiers de sauvegarde exportés sont chiffrés via l'API native Windows **`CryptProtectData` / `CryptUnprotectData`** (`crypt32.dll`).
   - Les données chiffrées sont liées cryptographiquement à l'utilisateur Windows courant et à la machine : un fichier `config.json` copié sur un autre PC ne peut pas être déchiffré.
2. **Verrou d'instance unique & Élévation Administrateur** (`src/main.py`, `src/utils/admin.py`) :
   - L'application demande automatiquement les privilèges Administrateur au démarrage (requis pour les sockets raw ICMP et les commandes `netsh interface ipv4`).
   - Un serveur local `QLocalServer` (`BahaaIT_Single_Instance_Lock`) empêche l'ouverture de doublons et ramène l'instance existante au premier plan.
3. **Suite de Tests Automatisés (`pytest`)** (`tests/test_core.py`) :
   - **27 tests unitaires et d'intégration** couvrant :
     - Les opérations CRUD SQLite et le calcul d'Uptime/SLA (`TestDatabase`).
     - La persistance `ConfigManager`, la résilience aux fichiers JSON corrompus et le chiffrement DPAPI (`TestConfig`, `TestAuth`).
     - Le scan de ports, la résolution DNS, le parsing `tracert` FR/EN, le parsing `netsh ipv4` FR/EN, le scanner Wi-Fi BSSID Windows 10/11 et la chaîne de diagnostic automatique en 5 étapes (`TestNetworkTools`, `TestBugFixes`, `TestWifiAndDiagnostic`).

---

## 5. Structure du Projet

```text
BahaaIT/
├── assets/                     # Icônes globales (.ico, .svg) et ressources graphiques
├── build_scripts/
│   ├── build.py                # Script de compilation PyInstaller (--onedir) + synchro de version
│   └── setup_compiler.iss      # Script Inno Setup générant Install_BahaaIT_v3.3.0.exe
├── src/
│   ├── main.py                 # Point d'entrée, UAC Admin, Single Instance, Splash Screen
│   ├── core/                   # Logique métier et moteurs réseau
│   │   ├── monitor.py          # Moteur de supervision ICMP continue
│   │   ├── net_config.py       # Lecture/écriture IP, Masque, Passerelle, DNS via netsh/psutil
│   │   ├── scanner.py          # Scanners LAN ARP/ICMP, Ports Asyncio, Tracert, Wi-Fi, Smart Diag
│   │   ├── speedtest.py        # Moteur Speedtest (Download, Upload, Ping, Jitter, Loss)
│   │   └── tools.py            # Utilitaires réseau (Whois, Nslookup, WoL, Subnet, MAC OUI)
│   ├── ui/
│   │   ├── main_window.py      # Fenêtre principale, barre latérale, en-tête temps réel, System Tray
│   │   ├── styles.qss          # Feuille de style globale Quantum Midnight (Dark Theme)
│   │   └── widgets/            # Vues des 11 modules et composants graphiques personnalisés
│   └── utils/
│       ├── admin.py            # Élévation UAC Windows (ShellExecuteExW)
│       ├── auth.py             # Client Supabase Auth + chiffrement Windows DPAPI 64-bit
│       ├── config.py           # Gestionnaire config.json (%LOCALAPPDATA%\BahaaIT)
│       ├── db.py               # Modèles SQLAlchemy & gestionnaire SQLite (%LOCALAPPDATA%\BahaaIT)
│       ├── email_notifier.py   # Notifications Email SMTP asynchrones
│       ├── i18n.py             # Dictionnaire de traduction complet Français / Anglais
│       ├── logger.py           # Journalisation applicative rotative
│       ├── pdf_generator.py    # Générateur de rapports PDF (ReportLab)
│       └── updater.py          # Vérification et téléchargement OTA depuis GitHub Releases
├── tests/
│   └── test_core.py            # Suite de 27 tests unitaires (pytest)
└── requirements.txt            # Dépendances Python épinglées
```

---

## 6. Recommandations & Évolutions Futures (Roadmap)

1. **Signature numérique du code (*Code Signing*)** :
   - Intégrer un certificat de signature de code (ex. *Microsoft Azure Trusted Signing* ou *Certum*) dans `build.py` et `setup_compiler.iss` afin d'authentifier l'éditeur auprès de Windows 11 (*SmartScreen* et *Smart App Control*).
2. **Séparation Dépôt Code Source / Dépôt Releases** :
   - Passer le dépôt contenant le code source en **Privé** et dédier un dépôt public léger (`bahaait-releases`) ou un bucket Supabase uniquement à la distribution des installateurs `.exe` pour l'Auto-Updater.
3. **Externalisation des alertes Email via Edge Function** :
   - Remplacer à terme le compte SMTP embarqué par défaut par une *Supabase Edge Function* pour les utilisateurs n'ayant pas configuré leur propre serveur SMTP.
