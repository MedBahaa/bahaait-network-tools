import csv
from datetime import datetime, timedelta
import json
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import func

from core.audit_logger import AuditLogger
from utils.db import (
    DatabaseManager,
    Host,
    InfrastructureDevice,
    InfrastructureVlan,
    MonitoringIncident,
    NetworkAnomaly,
    NetworkSite,
    PingMeasurement,
    SNMPDevice,
)

CONNECTIVITY_MODES = ("LOCAL", "VPN", "REMOTE_AUTHORIZED")


def _clean_site_code(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", str(name or "SITE").strip()).strip("-").upper()
    slug = slug[:14] or "SITE"
    return f"{slug}-{uuid.uuid4().hex[:5].upper()}"


class SiteManager:
    """Hierarchical Multi-Site Infrastructure manager integrated with monitoring and inventory."""

    def __init__(
        self,
        db: DatabaseManager,
        audit_logger: Optional[AuditLogger] = None,
        config_manager: Any = None,
    ) -> None:
        self.db = db
        self.audit = audit_logger or AuditLogger(db)
        self.config = config_manager

    @staticmethod
    def _site_to_dict(s: NetworkSite) -> Dict[str, Any]:
        return {
            "id": s.id,
            "site_code": s.site_code,
            "organization": s.organization or "Default Organization",
            "region": s.region or "Default Region",
            "parent_site_id": s.parent_site_id,
            "name": s.name,
            "description": s.description or "",
            "address": s.address or "",
            "contact_name": s.contact_name or "",
            "contact_email": s.contact_email or "",
            "contact_phone": s.contact_phone or "",
            "network_ranges": json.loads(s.network_ranges_json or "[]"),
            "default_gateway": s.default_gateway or "",
            "dns_servers": json.loads(s.dns_servers_json or "[]"),
            "isp_name": s.isp_name or "",
            "wan_info": json.loads(s.wan_info_json or "{}"),
            "connectivity_mode": s.connectivity_mode or "LOCAL",
            "polling_profile": json.loads(s.polling_profile_json or "{}"),
            "created_at": s.created_at,
            "updated_at": s.updated_at,
        }

    def create_site(self, data: Dict[str, Any]) -> Dict[str, Any]:
        name = str(data.get("name", "")).strip()
        if not name:
            raise ValueError("Site name is required.")

        mode = str(data.get("connectivity_mode", "LOCAL")).upper()
        if mode not in CONNECTIVITY_MODES:
            mode = "LOCAL"

        site_code = str(data.get("site_code") or "").strip() or _clean_site_code(name)

        with self.db.Session() as session:
            existing = session.query(NetworkSite).filter(
                func.lower(NetworkSite.name) == name.lower()
            ).first()
            if existing:
                raise ValueError(f"A site named '{name}' already exists.")

            row = NetworkSite(
                site_code=site_code,
                organization=str(data.get("organization") or "Default Organization").strip(),
                region=str(data.get("region") or "Default Region").strip(),
                parent_site_id=data.get("parent_site_id"),
                name=name,
                description=str(data.get("description") or "").strip(),
                address=str(data.get("address") or "").strip(),
                contact_name=str(data.get("contact_name") or "").strip(),
                contact_email=str(data.get("contact_email") or "").strip(),
                contact_phone=str(data.get("contact_phone") or "").strip(),
                network_ranges_json=json.dumps(list(data.get("network_ranges") or [])),
                default_gateway=str(data.get("default_gateway") or "").strip(),
                dns_servers_json=json.dumps(list(data.get("dns_servers") or [])),
                isp_name=str(data.get("isp_name") or "").strip(),
                wan_info_json=json.dumps(dict(data.get("wan_info") or {})),
                connectivity_mode=mode,
                polling_profile_json=json.dumps(dict(data.get("polling_profile") or {})),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            created = self._site_to_dict(row)

        self.audit.record_event(
            operation="SITE_CREATED",
            site_id=created["id"],
            site_name=created["name"],
            new_value={
                "site_code": created["site_code"],
                "organization": created["organization"],
                "region": created["region"],
                "connectivity_mode": created["connectivity_mode"],
            },
            detail=f"Site '{created['name']}' created in {created['organization']} / {created['region']}",
        )
        return created

    def get_site(self, site_id: int) -> Optional[Dict[str, Any]]:
        with self.db.Session() as session:
            row = session.query(NetworkSite).filter_by(id=int(site_id)).first()
            return self._site_to_dict(row) if row else None

    def get_site_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        clean = str(name or "").strip()
        if not clean:
            return None
        with self.db.Session() as session:
            row = session.query(NetworkSite).filter(
                func.lower(NetworkSite.name) == clean.lower()
            ).first()
            return self._site_to_dict(row) if row else None

    def get_or_create_site(self, name: str, organization: str = "Default Organization", region: str = "Default Region") -> Dict[str, Any]:
        existing = self.get_site_by_name(name)
        if existing:
            return existing
        return self.create_site({"name": name, "organization": organization, "region": region})

    def list_sites(
        self,
        organization: Optional[str] = None,
        region: Optional[str] = None,
        search: str = "",
    ) -> List[Dict[str, Any]]:
        with self.db.Session() as session:
            q = session.query(NetworkSite)
            if organization:
                q = q.filter(NetworkSite.organization == organization)
            if region:
                q = q.filter(NetworkSite.region == region)
            rows = q.order_by(NetworkSite.organization.asc(), NetworkSite.region.asc(), NetworkSite.name.asc()).all()
            items = [self._site_to_dict(r) for r in rows]

        term = str(search or "").strip().lower()
        if not term:
            return items
        return [
            s
            for s in items
            if (
                term in s["name"].lower()
                or term in s["site_code"].lower()
                or term in s["organization"].lower()
                or term in s["region"].lower()
                or term in s["address"].lower()
                or any(term in str(r).lower() for r in s["network_ranges"])
            )
        ]

    def update_site(self, site_id: int, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self.db.Session() as session:
            row = session.query(NetworkSite).filter_by(id=int(site_id)).first()
            if not row:
                return None
            prev = self._site_to_dict(row)

            json_map = {
                "network_ranges": "network_ranges_json",
                "dns_servers": "dns_servers_json",
                "wan_info": "wan_info_json",
                "polling_profile": "polling_profile_json",
            }
            for k, v in updates.items():
                if k in json_map:
                    setattr(row, json_map[k], json.dumps(v or ([] if k in ("network_ranges", "dns_servers") else {})))
                elif k == "connectivity_mode":
                    mode = str(v or "LOCAL").upper()
                    if mode in CONNECTIVITY_MODES:
                        row.connectivity_mode = mode
                elif hasattr(row, k) and k not in ("id", "created_at"):
                    setattr(row, k, v)
            row.updated_at = datetime.utcnow()
            session.commit()
            session.refresh(row)
            updated = self._site_to_dict(row)

        self.audit.record_event(
            operation="SITE_UPDATED",
            site_id=updated["id"],
            site_name=updated["name"],
            previous_value={"name": prev["name"], "address": prev["address"], "default_gateway": prev["default_gateway"]},
            new_value={"name": updated["name"], "address": updated["address"], "default_gateway": updated["default_gateway"]},
            detail=f"Updated site '{updated['name']}'",
        )
        return updated

    def delete_site(self, site_id: int) -> bool:
        with self.db.Session() as session:
            row = session.query(NetworkSite).filter_by(id=int(site_id)).first()
            if not row:
                return False
            snap = self._site_to_dict(row)
            session.delete(row)
            session.commit()

        self.audit.record_event(
            operation="SITE_DELETED",
            site_id=snap["id"],
            site_name=snap["name"],
            previous_value={"site_code": snap["site_code"], "name": snap["name"]},
            detail=f"Deleted site '{snap['name']}'",
        )
        return True

    def _effective_device_statuses(
        self,
        session: Any,
        devices: List[InfrastructureDevice],
    ) -> Tuple[int, int, int, int, List[str], List[int]]:
        """Resolve canonical UP/DOWN/DEGRADED/UNKNOWN counts using linked SNMP/Host telemetry when present."""
        snmp_ids = [d.snmp_device_id for d in devices if d.snmp_device_id is not None]
        host_ids = [d.host_id for d in devices if d.host_id is not None]
        ips = [d.management_ip for d in devices if d.management_ip]

        snmp_status_by_id: Dict[int, str] = {}
        if snmp_ids:
            for sid, st in session.query(SNMPDevice.id, SNMPDevice.status).filter(SNMPDevice.id.in_(snmp_ids)).all():
                snmp_status_by_id[int(sid)] = str(st or "UNKNOWN").upper()

        online = offline = degraded = unknown = 0
        for d in devices:
            raw_st = str(d.status or "UNKNOWN").upper()
            if d.snmp_device_id and int(d.snmp_device_id) in snmp_status_by_id:
                raw_st = snmp_status_by_id[int(d.snmp_device_id)]
            if raw_st in ("UP", "ONLINE", "OK"):
                online += 1
            elif raw_st in ("DEGRADED", "WARNING", "RECOVERING"):
                degraded += 1
            elif raw_st in ("DOWN", "OFFLINE", "CRITICAL"):
                offline += 1
            else:
                unknown += 1
        return online, offline, degraded, unknown, ips, snmp_ids

    def get_site_dashboard(self, site_id: int) -> Dict[str, Any]:
        with self.db.Session() as session:
            site = session.query(NetworkSite).filter_by(id=int(site_id)).first()
            if not site:
                raise ValueError(f"Site ID {site_id} not found.")
            site_dict = self._site_to_dict(site)
            devices = session.query(InfrastructureDevice).filter_by(site_id=int(site_id)).all()
            online, offline, degraded, unknown, ips, snmp_ids = self._effective_device_statuses(session, devices)
            total = len(devices)
            known_total = online + offline + degraded
            avail_pct = round(((online + degraded * 0.5) / known_total) * 100.0, 2) if known_total > 0 else 0.0

            active_incidents = 0
            avg_latency_ms: Optional[float] = None
            if ips:
                active_incidents = (
                    session.query(MonitoringIncident)
                    .filter(
                        MonitoringIncident.host_address.in_(ips),
                        MonitoringIncident.status.in_(("DETECTED", "ACKNOWLEDGED")),
                    )
                    .count()
                )
                since = datetime.utcnow() - timedelta(hours=24)
                avg_val = (
                    session.query(func.avg(PingMeasurement.latency_ms))
                    .filter(
                        PingMeasurement.host_address.in_(ips),
                        PingMeasurement.timestamp >= since,
                        PingMeasurement.latency_ms.isnot(None),
                    )
                    .scalar()
                )
                if avg_val is not None:
                    avg_latency_ms = round(float(avg_val), 2)

            active_anomalies = 0
            if snmp_ids or ips:
                q_anom = session.query(NetworkAnomaly).filter(
                    NetworkAnomaly.status.in_(("ACTIVE", "ACKNOWLEDGED"))
                )
                if snmp_ids and ips:
                    q_anom = q_anom.filter(
                        (NetworkAnomaly.device_id.in_(snmp_ids)) | (NetworkAnomaly.device_ip.in_(ips))
                    )
                elif snmp_ids:
                    q_anom = q_anom.filter(NetworkAnomaly.device_id.in_(snmp_ids))
                else:
                    q_anom = q_anom.filter(NetworkAnomaly.device_ip.in_(ips))
                active_anomalies = q_anom.count()

            vlan_count = (
                session.query(InfrastructureVlan.vlan_number)
                .filter(InfrastructureVlan.site_id == int(site_id))
                .distinct()
                .count()
            )
            if vlan_count == 0 and devices:
                dev_ids = [d.id for d in devices]
                vlan_count = (
                    session.query(InfrastructureVlan.vlan_number)
                    .filter(InfrastructureVlan.device_id.in_(dev_ids))
                    .distinct()
                    .count()
                )

            wan_status = str(site_dict["wan_info"].get("status") or "").upper()
            if not wan_status:
                if site_dict["default_gateway"]:
                    gw_dev = next((d for d in devices if d.management_ip == site_dict["default_gateway"]), None)
                    if gw_dev:
                        wan_status = str(gw_dev.status or "UNKNOWN").upper()
                    else:
                        wan_status = "UNKNOWN"
                else:
                    wan_status = "UNKNOWN"

            return {
                "site": site_dict,
                "site_id": site_dict["id"],
                "site_name": site_dict["name"],
                "organization": site_dict["organization"],
                "region": site_dict["region"],
                "connectivity_mode": site_dict["connectivity_mode"],
                "total_devices": total,
                "online_devices": online,
                "offline_devices": offline,
                "degraded_devices": degraded,
                "unknown_devices": unknown,
                "active_incidents": active_incidents,
                "active_anomalies": active_anomalies,
                "wan_status": wan_status,
                "avg_latency_ms": avg_latency_ms,
                "availability_pct": avail_pct,
                "vlan_count": vlan_count,
            }

    def get_site_hierarchy(self) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """Build Organization -> Region -> Sites hierarchy enriched with device & VLAN counts."""
        sites = self.list_sites()
        hierarchy: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        with self.db.Session() as session:
            dev_counts = dict(
                session.query(InfrastructureDevice.site_id, func.count(InfrastructureDevice.id))
                .group_by(InfrastructureDevice.site_id)
                .all()
            )
            vlan_counts = dict(
                session.query(InfrastructureVlan.site_id, func.count(func.distinct(InfrastructureVlan.vlan_number)))
                .group_by(InfrastructureVlan.site_id)
                .all()
            )
        for s in sites:
            org = s["organization"] or "Default Organization"
            reg = s["region"] or "Default Region"
            enriched = dict(s)
            enriched["device_count"] = int(dev_counts.get(s["id"], 0))
            enriched["vlan_count"] = int(vlan_counts.get(s["id"], 0))
            hierarchy.setdefault(org, {}).setdefault(reg, []).append(enriched)
        return hierarchy

    def compare_sites(self) -> List[Dict[str, Any]]:
        """Return comparative availability, incidents, and latency table across all sites."""
        comparisons: List[Dict[str, Any]] = []
        for s in self.list_sites():
            comparisons.append(self.get_site_dashboard(s["id"]))
        return comparisons

    def migrate_legacy_config_sites(self, config_manager: Any = None) -> Dict[str, int]:
        """Non-destructively migrate config.json legacy 'sites' list into SQLite sites & devices."""
        cfg = config_manager or self.config
        if cfg is None:
            return {"sites_created": 0, "devices_created": 0}
        legacy_entries = cfg.get("sites", []) or []
        sites_created = 0
        devices_created = 0

        for entry in legacy_entries:
            if not isinstance(entry, dict):
                continue
            dev_name = str(entry.get("name") or "").strip()
            dev_ip = str(entry.get("ip") or "").strip()
            site_name = str(entry.get("site") or "").strip() or "Main Office"
            if not dev_name or not dev_ip:
                continue

            site = self.get_site_by_name(site_name)
            if not site:
                site = self.create_site({"name": site_name})
                sites_created += 1

            with self.db.Session() as session:
                exists = session.query(InfrastructureDevice).filter(
                    InfrastructureDevice.management_ip == dev_ip,
                    InfrastructureDevice.hostname == dev_name,
                ).first()
                if not exists:
                    row = InfrastructureDevice(
                        device_uid=f"DEV-{uuid.uuid4().hex[:10].upper()}",
                        site_id=site["id"],
                        hostname=dev_name,
                        management_ip=dev_ip,
                        discovery_source="LEGACY_SITES_MIGRATION",
                    )
                    session.add(row)
                    session.commit()
                    devices_created += 1

        return {"sites_created": sites_created, "devices_created": devices_created}

    def export_site_csv(self, site_id: int, file_path: str) -> None:
        dash = self.get_site_dashboard(site_id)
        with self.db.Session() as session:
            devs = (
                session.query(InfrastructureDevice)
                .filter_by(site_id=int(site_id))
                .order_by(InfrastructureDevice.hostname.asc())
                .all()
            )
        headers = [
            "Site", "Organization", "Region", "Hostname", "Management IP", "MAC",
            "Vendor", "Model", "Category", "Role", "Rack", "Status",
            "Serial Number", "Firmware", "Owner", "Warranty Expiration",
        ]
        s = dash["site"]
        with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for d in devs:
                writer.writerow([
                    s["name"], s["organization"], s["region"],
                    d.hostname, d.management_ip, d.mac_address or "",
                    d.vendor or "", d.model or "", d.category or "",
                    d.role or "", d.rack_location or "", d.status or "UNKNOWN",
                    d.serial_number or "", d.firmware_version or "",
                    d.equipment_owner or "", d.warranty_expiration or "",
                ])

    def export_site_pdf(self, site_id: int, file_path: str) -> Tuple[bool, str]:
        dash = self.get_site_dashboard(site_id)
        with self.db.Session() as session:
            rows = (
                session.query(InfrastructureDevice)
                .filter_by(site_id=int(site_id))
                .order_by(InfrastructureDevice.hostname.asc())
                .all()
            )
            devs = [
                {
                    "hostname": d.hostname,
                    "management_ip": d.management_ip,
                    "mac_address": d.mac_address or "",
                    "vendor": d.vendor or "",
                    "model": d.model or "",
                    "category": d.category or "",
                    "rack_location": d.rack_location or "",
                    "status": d.status or "UNKNOWN",
                    "serial_number": d.serial_number or "",
                    "firmware_version": d.firmware_version or "",
                }
                for d in rows
            ]
        from utils.pdf_generator import PDFReportGenerator
        return PDFReportGenerator().generate_site_report(dash["site"], dash, devs, save_path=file_path)
