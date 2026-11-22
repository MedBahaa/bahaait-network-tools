# BahaaIT Network Tools v3.6.0 — Release Notes

**Roadmap 03 — Infrastructure Management Platform**

## Nouveautés Majeures / Major Features

1. **Network Topology (`TopologyView`, `src/core/topology_discovery.py`, `src/core/topology_graph.py`)**
   - Découverte automatique multi-sources (LLDP, CDP, BRIDGE-MIB / Q-BRIDGE MAC FDB, IP Routing table, SNMP system/interfaces, table ARP locale).
   - Identification constructeur via OUI (`oui_lookup.py`) sans jamais deviner la catégorie depuis le seul OUI MAC ; inférence prudente de switch non managé uniquement lorsque >= 2 MACs partagent un port non-LLDP/CDP.
   - Carte interactive `QGraphicsView` avec 4 modes (`PHYSICAL`, `LOGICAL`, `VLAN`, `SITE`), zoom/pan, glisser-déposer, disposition automatique déterministe (`200+` nœuds), sauvegarde de disposition par vue/site, export PNG et inspecteur complet.

2. **Advanced Device Inventory (`InventoryView`, `src/core/inventory_manager.py`)**
   - Inventaire centralisé sur 11 catégories, synchronisation non destructive depuis `snmp_devices` / `hosts` / configuration sites historique.
   - Suivi cycle de vie (achat, garantie, rappels maintenance, baies/racks, tags, champs personnalisés), détection de doublons IP/MAC et exports CSV / PDF Corporate.

3. **VLAN Management (`VLANView`, `src/core/vlan_manager.py`)**
   - Synchronisation VLANs SNMP + parseurs CLI constructeurs (Cisco IOS/IOS XE, Ruckus ICX, Fortinet FortiGate).
   - Matrice multi-switchs et détection automatique d'incohérences (`NAME_MISMATCH`, `TRUNK_VLAN_GAP`, `INACTIVE_WITH_PORTS`).
   - Planificateur CLI contrôlé avec prévisualisation constructeur, blocage de suppression VLAN 1 / caractères dangereux et dialogue de confirmation explicite.

4. **Configuration Backup, Visual Diff, Templates & Controlled Restore (`BackupView`, `src/core/backup_manager.py`, `backup_adapters.py`, `config_diff.py`, `config_templates.py`)**
   - Adaptateurs Cisco IOS, Ruckus ICX, Ruckus SmartZone API, FortiGate et Generic SSH.
   - Chiffrement au repos **Windows DPAPI (`BHITENC1:`) + zlib + SHA-256** (intégrité + détection d'altération disque), isolation des pannes en lots par site.
   - Comparaison visuelle côte à côte / unifiée avec masquage automatique des secrets, 8 modèles paramétrables et restauration contrôlée avec sauvegarde `PRE_RESTORE` obligatoire et confirmation explicite.

5. **Network Access & Device Administration (`RemoteView` — Centre d'Accès Réseau, `src/core/ssh_access.py`)**
   - Multi-sessions SSH/Telnet/Série COM, profils SSH chiffrés DPAPI, vérification stricte `known_hosts` (`StrictVerifyHostKeyPolicy`, sans `AutoAddPolicy`).
   - Classification de sécurité CLI (`READ_ONLY` / `MODIFYING` / `DESTRUCTIVE`), commandes diagnostic par constructeur, export de journaux masqués, raccourcis HTTPS / RDP (`mstsc`) / SNMP.

6. **Multi-Site Management & Immutable Audit Trail (`SitesView`, `AuditView`, `src/core/site_manager.py`, `src/core/audit_logger.py`)**
   - Arborescence hiérarchique `Organisation -> Région -> Site`, KPIs de disponibilité/latence/incidents par site et comparaison multi-sites.
   - Base SQLite étendue à **28 tables** avec triggers d'immuabilité sur `infrastructure_audit` (`trg_infra_audit_no_update`, `trg_infra_audit_no_delete`) et empreinte SHA-256 vérifiable par enregistrement.
