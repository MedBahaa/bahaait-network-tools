# BahaaIT Network Tools v3.6.1 — Release Notes

**Topologie Réseau Live Pro (style Omada / UniFi) & Refonte UI Quantum Midnight v2**

## 1. Topologie Réseau Pro (`TopologyView`, `topology_discovery.py`, `topology_graph.py`)

- **Découverte en direct isolée du réseau actuel** : cliquer sur **Découvrir Topologie** scanne uniquement les équipements présents à l'instant même (balayage sous-réseau actif, table ARP locale filtrée, passerelle par défaut, poste local et équipements SNMP joignables LLDP/CDP/FDB/Routage), sans afficher les équipements hors ligne d'anciens sites et sans écriture silencieuse en base SQLite.
- **Ajout direct au Site (1 carte ou lot complet)** : bouton **+ Ajouter au Site...** dans l'inspecteur, clic droit sur une carte, ou **+ Tout Ajouter au Site...** dans le bandeau Live via `AssignToSiteDialog` (assignation à un site existant ou création d'un nouveau site à la volée pré-rempli avec la passerelle et le CIDR détectés).
- **Cartes matérielles Pro style TP-Link Omada / Ubiquiti UniFi** : grille de points, cartes 212x96 avec icônes vectorielles dédiées (Routeur/Passerelle, Firewall, Switch, Borne Wi-Fi, Serveur, PC local, Imprimante, Onduleur), couronne supérieure **INTERNET / WAN** pour la passerelle, pastille latence/statut, badges `PASSERELLE` / `CE PC` / `NOUVEAU` / `+SITE` et compteurs directionnels Uplink/Downstream.
- **Liens courbes de Bézier fléchés & « qui donne à qui »** : orientation automatique *Passerelle -> Switch -> AP / Terminal*, pointes de flèches directionnelles, menu contextuel (`Définir comme Passerelle`, copie IP/MAC, Centre d'Accès, Interface Web) et inspecteur détaillant **Alimenté par (Uplink)** et **Alimente (Downstream)**.

## 2. Refonte UI/UX Quantum Midnight v2 (Audit complet 19 écrans)

- **Design System unifié** (`src/ui/styles.qss` + `assets/icons/*.svg`) : 6 icônes vectorielles SVG natives remplaçant les data-URI CSS ignorées par Qt, conteneurs isolés (`#PanelCard`, `#FilterBar`, `#KpiCard`, `#LiveBanner`) éliminant toute cascade de bordures sur `QLabel`, et fenêtre principale librement redimensionnable avec animation de transition fluide.
- **Lisibilité & Ergonomie multi-écrans** : en-têtes/filtres sur 2 lignes sans débordement ni troncature (`Dashboard`, `Monitoring`, `SNMP`, `Syslog`, `Intelligence`, `Scanners`, `Outils IT`, `Speedtest`, `Config IPv4`, `Paramètres`, `Gestionnaire Web`, `Terminal Distant`, `Multi-Sites`, `Inventaire`, `VLANs`, `Sauvegardes`, `Audit`), échappement complet des mnémoniques Qt (`&`) et listes déroulantes ajustées au contenu.
- **Sécurité & Stabilité** : suppression de tout secret SMTP en clair dans l'interface, validation IP/port renforcée, gestion propre du cycle de vie `QThread`, des workers séquentiels (`HostDetailsDialog`, `ToolsView`, `SpeedtestView`) et de la barre de menus / zone de notification système.

## 3. Qualité, Documentation & Packaging

- **Documentation PDF officielle** (`docs/Documentation_BahaaIT_Network_Tools.pdf`) mise à jour avec toutes les évolutions v3.6.1.
- **Couverture automatisée** : `120` tests `pytest` incluant le nouvel audit UI/UX (`tests/test_ui_design_audit.py`), les tests de découverte Live isolée et d'ajout de site (`tests/test_v360_topology.py`).
- **Installateur Windows** (`Install_BahaaIT_v3.6.1.exe`) mis à jour avec prise en charge complète du téléchargement direct OTA.
