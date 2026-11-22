import csv
from datetime import date, datetime, timedelta
import json
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import func

from core.audit_logger import AuditLogger
from core.monitoring_state import validate_target_address
from core.oui_lookup import lookup_vendor_by_mac, normalize_mac
from core.site_manager import SiteManager
from utils.db import DatabaseManager, Host, InfrastructureDevice, NetworkSite, SNMPDevice

DEVICE_CATEGORIES: Tuple[str, ...] = (
    "Core Switch",
    "Distribution Switch",
    "Access Switch",
    "Router",
    "Firewall",
    "Wireless Controller",
    "Wireless Access Point",
    "Server",
    "Printer",
    "UPS",
    "Other",
)


def _norm_category(raw: str) -> str:
    val = str(raw or "").strip()
    if not val:
        return "Other"
    for cat in DEVICE_CATEGORIES:
        if cat.lower() == val.lower():
            return cat
    low = val.lower()
    if "core" in low:
        return "Core Switch"
    if "distrib" in low:
        return "Distribution Switch"
    if "switch" in low:
        return "Access Switch"
    if "router" in low:
        return "Router"
    if "firewall" in low or "fortigate" in low:
        return "Firewall"
    if "controller" in low or "smartzone" in low or "wlc" in low:
        return "Wireless Controller"
    if "access point" in low or low == "ap" or "wifi" in low:
        return "Wireless Access Point"
    if "server" in low or "appliance" in low:
        return "Server"
    if "print" in low:
        return "Printer"
    if "ups" in low or "onduleur" in low:
        return "UPS"
    return "Other"


class InventoryManager:
    """Centralized enterprise infrastructure device inventory and asset lifecycle manager."""

    def __init__(
        self,
        db: DatabaseManager,
        audit_logger: Optional[AuditLogger] = None,
        site_manager: Optional[SiteManager] = None,
    ) -> None:
        self.db = db
        self.audit = audit_logger or AuditLogger(db)
        self.site_manager = site_manager or SiteManager(db, audit_logger=self.audit)

    @staticmethod
    def _dev_to_dict(d: InfrastructureDevice, site_names: Optional[Dict[int, str]] = None) -> Dict[str, Any]:
        return {
            "id": d.id,
            "device_uid": d.device_uid,
            "site_id": d.site_id,
            "site_name": (site_names or {}).get(d.site_id, "") if d.site_id else "",
            "snmp_device_id": d.snmp_device_id,
            "host_id": d.host_id,
            "hostname": d.hostname,
            "management_ip": d.management_ip,
            "mac_address": d.mac_address or "",
            "vendor": d.vendor or "Unknown",
            "model": d.model or "",
            "serial_number": d.serial_number or "",
            "firmware_version": d.firmware_version or "",
            "category": d.category or "Other",
            "role": d.role or "",
            "rack_location": d.rack_location or "",
            "management_protocol": d.management_protocol or "SNMP",
            "snmp_profile": d.snmp_profile or "",
            "ssh_profile_id": d.ssh_profile_id,
            "discovery_source": d.discovery_source or "MANUAL",
            "status": d.status or "UNKNOWN",
            "tags": json.loads(d.tags_json or "[]"),
            "device_group": d.device_group or "",
            "custom_fields": json.loads(d.custom_fields_json or "{}"),
            "purchase_date": d.purchase_date or "",
            "warranty_expiration": d.warranty_expiration or "",
            "manufacturer": d.manufacturer or "",
            "support_info": d.support_info or "",
            "maintenance_notes": d.maintenance_notes or "",
            "equipment_owner": d.equipment_owner or "",
            "maintenance_reminder_date": d.maintenance_reminder_date or "",
            "last_discovery": d.last_discovery,
            "last_monitoring_check": d.last_monitoring_check,
            "created_at": d.created_at,
            "updated_at": d.updated_at,
        }

    def check_duplicate_ip(self, management_ip: str, exclude_device_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        ip = str(management_ip or "").strip()
        if not ip:
            return None
        with self.db.Session() as session:
            q = session.query(InfrastructureDevice).filter(InfrastructureDevice.management_ip == ip)
            if exclude_device_id is not None:
                q = q.filter(InfrastructureDevice.id != int(exclude_device_id))
            dup = q.first()
            return self._dev_to_dict(dup) if dup else None

    def check_duplicate_mac(self, mac_address: str, exclude_device_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        norm_mac = normalize_mac(mac_address)
        if not norm_mac:
            return None
        with self.db.Session() as session:
            q = session.query(InfrastructureDevice).filter(InfrastructureDevice.mac_address == norm_mac)
            if exclude_device_id is not None:
                q = q.filter(InfrastructureDevice.id != int(exclude_device_id))
            dup = q.first()
            return self._dev_to_dict(dup) if dup else None

    def find_duplicate_ips(self) -> Dict[str, List[Dict[str, Any]]]:
        with self.db.Session() as session:
            dup_vals = [
                r[0]
                for r in session.query(InfrastructureDevice.management_ip)
                .group_by(InfrastructureDevice.management_ip)
                .having(func.count(InfrastructureDevice.id) > 1)
                .all()
            ]
            if not dup_vals:
                return {}
            rows = (
                session.query(InfrastructureDevice)
                .filter(InfrastructureDevice.management_ip.in_(dup_vals))
                .order_by(InfrastructureDevice.management_ip.asc())
                .all()
            )
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for r in rows:
                grouped.setdefault(r.management_ip, []).append(self._dev_to_dict(r))
            return grouped

    def find_duplicate_macs(self) -> Dict[str, List[Dict[str, Any]]]:
        with self.db.Session() as session:
            dup_vals = [
                r[0]
                for r in session.query(InfrastructureDevice.mac_address)
                .filter(InfrastructureDevice.mac_address != "")
                .group_by(InfrastructureDevice.mac_address)
                .having(func.count(InfrastructureDevice.id) > 1)
                .all()
            ]
            if not dup_vals:
                return {}
            rows = (
                session.query(InfrastructureDevice)
                .filter(InfrastructureDevice.mac_address.in_(dup_vals))
                .order_by(InfrastructureDevice.mac_address.asc())
                .all()
            )
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for r in rows:
                grouped.setdefault(r.mac_address, []).append(self._dev_to_dict(r))
            return grouped

    def add_device(self, data: Dict[str, Any], allow_duplicate_ip: bool = False) -> Dict[str, Any]:
        hostname = str(data.get("hostname") or "").strip()
        mgmt_ip = str(data.get("management_ip") or "").strip()
        if not hostname:
            raise ValueError("Hostname is required.")
        if not mgmt_ip:
            raise ValueError("Management IP is required.")
        validate_target_address(mgmt_ip)

        if not allow_duplicate_ip:
            existing_ip = self.check_duplicate_ip(mgmt_ip)
            if existing_ip:
                raise ValueError(f"Duplicate management IP '{mgmt_ip}' already assigned to '{existing_ip['hostname']}'.")

        norm_mac = normalize_mac(data.get("mac_address", ""))
        vendor = str(data.get("vendor") or "").strip()
        if (not vendor or vendor.lower() == "unknown") and norm_mac:
            vendor = lookup_vendor_by_mac(norm_mac)
        if not vendor:
            vendor = "Unknown"

        site_id = data.get("site_id")
        if site_id is None and data.get("site_name"):
            site = self.site_manager.get_or_create_site(str(data["site_name"]).strip())
            site_id = site["id"]

        device_uid = str(data.get("device_uid") or "").strip() or f"DEV-{uuid.uuid4().hex[:10].upper()}"
        tags = [str(t).strip() for t in (data.get("tags") or []) if str(t).strip()]
        custom_fields = dict(data.get("custom_fields") or {})

        with self.db.Session() as session:
            row = InfrastructureDevice(
                device_uid=device_uid,
                site_id=site_id,
                snmp_device_id=data.get("snmp_device_id"),
                host_id=data.get("host_id"),
                hostname=hostname,
                management_ip=mgmt_ip,
                mac_address=norm_mac,
                vendor=vendor,
                model=str(data.get("model") or "").strip(),
                serial_number=str(data.get("serial_number") or "").strip(),
                firmware_version=str(data.get("firmware_version") or "").strip(),
                category=_norm_category(data.get("category", "Other")),
                role=str(data.get("role") or "").strip(),
                rack_location=str(data.get("rack_location") or "").strip(),
                management_protocol=str(data.get("management_protocol") or "SNMP").strip(),
                snmp_profile=str(data.get("snmp_profile") or "").strip(),
                ssh_profile_id=data.get("ssh_profile_id"),
                discovery_source=str(data.get("discovery_source") or "MANUAL").strip(),
                status=str(data.get("status") or "UNKNOWN").upper(),
                tags_json=json.dumps(tags),
                device_group=str(data.get("device_group") or "").strip(),
                custom_fields_json=json.dumps(custom_fields),
                purchase_date=str(data.get("purchase_date") or "").strip(),
                warranty_expiration=str(data.get("warranty_expiration") or "").strip(),
                manufacturer=str(data.get("manufacturer") or vendor).strip(),
                support_info=str(data.get("support_info") or "").strip(),
                maintenance_notes=str(data.get("maintenance_notes") or "").strip(),
                equipment_owner=str(data.get("equipment_owner") or "").strip(),
                maintenance_reminder_date=str(data.get("maintenance_reminder_date") or "").strip(),
                last_discovery=data.get("last_discovery"),
                last_monitoring_check=data.get("last_monitoring_check"),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            site_map = {r.id: r.name for r in session.query(NetworkSite).all()}
            created = self._dev_to_dict(row, site_map)

        self.audit.record_event(
            operation="DEVICE_CREATED",
            site_id=created["site_id"],
            site_name=created["site_name"],
            device_id=created["id"],
            device_name=created["hostname"],
            device_ip=created["management_ip"],
            new_value={
                "hostname": created["hostname"],
                "management_ip": created["management_ip"],
                "category": created["category"],
                "vendor": created["vendor"],
            },
            detail=f"Device '{created['hostname']}' ({created['management_ip']}) added to inventory",
        )
        return created

    def get_device(self, device_id: int) -> Optional[Dict[str, Any]]:
        with self.db.Session() as session:
            row = session.query(InfrastructureDevice).filter_by(id=int(device_id)).first()
            if not row:
                return None
            site_map = {r.id: r.name for r in session.query(NetworkSite).all()}
            return self._dev_to_dict(row, site_map)

    def get_device_by_ip(self, management_ip: str) -> Optional[Dict[str, Any]]:
        with self.db.Session() as session:
            row = session.query(InfrastructureDevice).filter_by(management_ip=str(management_ip).strip()).first()
            if not row:
                return None
            site_map = {r.id: r.name for r in session.query(NetworkSite).all()}
            return self._dev_to_dict(row, site_map)

    def update_device(
        self,
        device_id: int,
        updates: Dict[str, Any],
        allow_duplicate_ip: bool = False,
    ) -> Optional[Dict[str, Any]]:
        with self.db.Session() as session:
            row = session.query(InfrastructureDevice).filter_by(id=int(device_id)).first()
            if not row:
                return None
            site_map = {r.id: r.name for r in session.query(NetworkSite).all()}
            prev = self._dev_to_dict(row, site_map)

            if "management_ip" in updates and updates["management_ip"] != row.management_ip:
                new_ip = str(updates["management_ip"]).strip()
                validate_target_address(new_ip)
                if not allow_duplicate_ip:
                    dup = (
                        session.query(InfrastructureDevice)
                        .filter(InfrastructureDevice.management_ip == new_ip, InfrastructureDevice.id != row.id)
                        .first()
                    )
                    if dup:
                        raise ValueError(f"Duplicate management IP '{new_ip}' already assigned to '{dup.hostname}'.")
                row.management_ip = new_ip

            if "site_id" not in updates and updates.get("site_name"):
                site = self.site_manager.get_or_create_site(str(updates["site_name"]).strip())
                row.site_id = site["id"]

            for k, v in updates.items():
                if k in ("id", "created_at", "device_uid", "site_name", "management_ip"):
                    continue
                if k == "mac_address":
                    row.mac_address = normalize_mac(v)
                elif k == "category":
                    row.category = _norm_category(v)
                elif k == "status":
                    row.status = str(v or "UNKNOWN").upper()
                elif k == "tags":
                    row.tags_json = json.dumps([str(t).strip() for t in (v or []) if str(t).strip()])
                elif k == "custom_fields":
                    row.custom_fields_json = json.dumps(dict(v or {}))
                elif hasattr(row, k):
                    setattr(row, k, v)

            row.updated_at = datetime.utcnow()
            session.commit()
            session.refresh(row)
            site_map = {r.id: r.name for r in session.query(NetworkSite).all()}
            updated = self._dev_to_dict(row, site_map)

        op = "IP_ADDRESS_MODIFIED" if prev["management_ip"] != updated["management_ip"] else "DEVICE_UPDATED"
        self.audit.record_event(
            operation=op,
            site_id=updated["site_id"],
            site_name=updated["site_name"],
            device_id=updated["id"],
            device_name=updated["hostname"],
            device_ip=updated["management_ip"],
            previous_value={
                "hostname": prev["hostname"],
                "management_ip": prev["management_ip"],
                "category": prev["category"],
                "site_id": prev["site_id"],
            },
            new_value={
                "hostname": updated["hostname"],
                "management_ip": updated["management_ip"],
                "category": updated["category"],
                "site_id": updated["site_id"],
            },
            detail=f"Updated device '{updated['hostname']}' ({updated['management_ip']})",
        )
        return updated

    def delete_device(self, device_id: int) -> bool:
        with self.db.Session() as session:
            row = session.query(InfrastructureDevice).filter_by(id=int(device_id)).first()
            if not row:
                return False
            site_map = {r.id: r.name for r in session.query(NetworkSite).all()}
            snap = self._dev_to_dict(row, site_map)
            session.delete(row)
            session.commit()

        self.audit.record_event(
            operation="DEVICE_DELETED",
            site_id=snap["site_id"],
            site_name=snap["site_name"],
            device_id=snap["id"],
            device_name=snap["hostname"],
            device_ip=snap["management_ip"],
            previous_value={"hostname": snap["hostname"], "management_ip": snap["management_ip"], "category": snap["category"]},
            detail=f"Deleted device '{snap['hostname']}' ({snap['management_ip']})",
        )
        return True

    def list_devices(
        self,
        site_id: Optional[int] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        vendor: Optional[str] = None,
        group: Optional[str] = None,
        tag: Optional[str] = None,
        search: str = "",
        limit: int = 2000,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        with self.db.Session() as session:
            site_map = {r.id: r.name for r in session.query(NetworkSite).all()}
            q = session.query(InfrastructureDevice)
            if site_id is not None:
                q = q.filter(InfrastructureDevice.site_id == int(site_id))
            if category:
                q = q.filter(InfrastructureDevice.category == category)
            if status:
                q = q.filter(InfrastructureDevice.status == str(status).upper())
            if vendor:
                q = q.filter(InfrastructureDevice.vendor == vendor)
            if group:
                q = q.filter(InfrastructureDevice.device_group == group)
            rows = (
                q.order_by(InfrastructureDevice.hostname.asc())
                .offset(max(0, int(offset)))
                .limit(max(1, int(limit)))
                .all()
            )
            items = [self._dev_to_dict(r, site_map) for r in rows]

        if tag:
            t_low = str(tag).strip().lower()
            items = [d for d in items if any(t.lower() == t_low for t in d["tags"])]

        term = str(search or "").strip().lower()
        if not term:
            return items
        return [
            d
            for d in items
            if (
                term in d["hostname"].lower()
                or term in d["management_ip"].lower()
                or term in d["mac_address"].lower()
                or term in d["vendor"].lower()
                or term in d["model"].lower()
                or term in d["serial_number"].lower()
                or term in d["site_name"].lower()
                or term in d["rack_location"].lower()
                or term in d["device_group"].lower()
                or any(term in t.lower() for t in d["tags"])
            )
        ]

    def sync_from_snmp_and_hosts(self) -> Dict[str, int]:
        """Synchronize SNMPDevice and Host monitoring records into unified inventory safely."""
        created = 0
        updated = 0
        with self.db.Session() as session:
            snmp_rows = session.query(SNMPDevice).all()
            host_rows = session.query(Host).all()
            sites_by_name = {s.name.lower(): s.id for s in session.query(NetworkSite).all()}

            for sdev in snmp_rows:
                existing = (
                    session.query(InfrastructureDevice)
                    .filter(
                        (InfrastructureDevice.snmp_device_id == sdev.id)
                        | (InfrastructureDevice.management_ip == sdev.ip_address)
                    )
                    .first()
                )
                site_id = None
                loc = str(sdev.location or sdev.sys_location or "").strip()
                if loc and loc.lower() in sites_by_name:
                    site_id = sites_by_name[loc.lower()]
                cat = _norm_category(sdev.device_type or sdev.profile_name)

                if existing:
                    existing.snmp_device_id = sdev.id
                    existing.vendor = sdev.vendor or existing.vendor
                    existing.model = sdev.model or existing.model
                    existing.firmware_version = sdev.firmware or existing.firmware_version
                    existing.snmp_profile = sdev.profile_name or existing.snmp_profile
                    existing.status = sdev.status or existing.status
                    if existing.site_id is None and site_id is not None:
                        existing.site_id = site_id
                    if sdev.last_poll:
                        existing.last_monitoring_check = sdev.last_poll
                        existing.last_discovery = sdev.last_poll
                    updated += 1
                else:
                    row = InfrastructureDevice(
                        device_uid=f"DEV-{uuid.uuid4().hex[:10].upper()}",
                        site_id=site_id,
                        snmp_device_id=sdev.id,
                        hostname=sdev.sys_name or sdev.name or sdev.ip_address,
                        management_ip=sdev.ip_address,
                        vendor=sdev.vendor or "Generic",
                        model=sdev.model or "",
                        firmware_version=sdev.firmware or "",
                        category=cat,
                        management_protocol=f"SNMP ({sdev.snmp_version})",
                        snmp_profile=sdev.profile_name or "",
                        discovery_source="SNMP_SYNC",
                        status=sdev.status or "UNKNOWN",
                        last_discovery=sdev.last_poll or datetime.utcnow(),
                        last_monitoring_check=sdev.last_poll,
                    )
                    session.add(row)
                    created += 1

            for h in host_rows:
                existing = (
                    session.query(InfrastructureDevice)
                    .filter(
                        (InfrastructureDevice.host_id == h.id)
                        | (InfrastructureDevice.management_ip == h.address)
                    )
                    .first()
                )
                if existing:
                    if existing.host_id is None:
                        existing.host_id = h.id
                else:
                    row = InfrastructureDevice(
                        device_uid=f"DEV-{uuid.uuid4().hex[:10].upper()}",
                        host_id=h.id,
                        hostname=h.label or h.address,
                        management_ip=h.address,
                        category=_norm_category(h.category or "Other"),
                        management_protocol="ICMP",
                        discovery_source="PING_HOST_SYNC",
                        status="UNKNOWN",
                    )
                    session.add(row)
                    created += 1

            session.commit()
        return {"created": created, "updated": updated}

    def get_maintenance_reminders(
        self,
        within_days: int = 30,
        reference_date: Optional[date] = None,
    ) -> List[Dict[str, Any]]:
        ref = reference_date or datetime.utcnow().date()
        horizon = ref + timedelta(days=int(within_days))
        reminders: List[Dict[str, Any]] = []
        for dev in self.list_devices(limit=5000):
            for field_name, kind in (
                ("warranty_expiration", "WARRANTY"),
                ("maintenance_reminder_date", "MAINTENANCE"),
            ):
                raw = str(dev.get(field_name) or "").strip()
                if not raw:
                    continue
                try:
                    dt = datetime.strptime(raw[:10], "%Y-%m-%d").date()
                except ValueError:
                    continue
                if dt <= horizon:
                    days_left = (dt - ref).days
                    reminders.append({
                        "device_id": dev["id"],
                        "hostname": dev["hostname"],
                        "management_ip": dev["management_ip"],
                        "site_name": dev["site_name"],
                        "reminder_kind": kind,
                        "due_date": dt.strftime("%Y-%m-%d"),
                        "days_remaining": days_left,
                        "expired": days_left < 0,
                        "owner": dev["equipment_owner"],
                    })
        reminders.sort(key=lambda r: r["days_remaining"])
        return reminders

    def import_csv(
        self,
        file_path: str,
        default_site_id: Optional[int] = None,
        skip_duplicates: bool = True,
    ) -> Dict[str, Any]:
        imported = 0
        skipped_duplicates = 0
        errors: List[str] = []

        with open(file_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader, start=2):
                norm = {str(k or "").strip().lower(): str(v or "").strip() for k, v in row.items()}
                hostname = (
                    norm.get("hostname")
                    or norm.get("name")
                    or norm.get("equipment")
                    or norm.get("device name")
                    or ""
                )
                ip = (
                    norm.get("management ip")
                    or norm.get("management_ip")
                    or norm.get("ip address")
                    or norm.get("ip")
                    or ""
                )
                if not hostname or not ip:
                    errors.append(f"Row {idx}: missing hostname or IP")
                    continue

                if skip_duplicates and self.check_duplicate_ip(ip):
                    skipped_duplicates += 1
                    continue

                site_id = default_site_id
                site_name = norm.get("site") or norm.get("site name") or norm.get("location") or ""
                if site_name:
                    site = self.site_manager.get_or_create_site(site_name)
                    site_id = site["id"]

                tags_raw = norm.get("tags", "")
                tags = [t.strip() for t in tags_raw.split(";") if t.strip()] if tags_raw else []
                payload = {
                    "hostname": hostname,
                    "management_ip": ip,
                    "mac_address": norm.get("mac") or norm.get("mac address") or norm.get("mac_address") or "",
                    "vendor": norm.get("vendor") or norm.get("manufacturer") or "",
                    "model": norm.get("model") or "",
                    "serial_number": norm.get("serial") or norm.get("serial number") or norm.get("serial_number") or "",
                    "firmware_version": norm.get("firmware") or norm.get("firmware version") or "",
                    "category": norm.get("category") or "Other",
                    "role": norm.get("role") or "",
                    "site_id": site_id,
                    "rack_location": norm.get("rack") or norm.get("rack / location") or "",
                    "management_protocol": norm.get("protocol") or norm.get("management protocol") or "SNMP",
                    "snmp_profile": norm.get("snmp profile") or norm.get("snmp_profile") or "",
                    "discovery_source": "CSV_IMPORT",
                    "tags": tags,
                    "device_group": norm.get("group") or norm.get("device_group") or "",
                    "purchase_date": norm.get("purchase date") or norm.get("purchase_date") or "",
                    "warranty_expiration": norm.get("warranty expiration") or norm.get("warranty_expiration") or "",
                    "equipment_owner": norm.get("owner") or norm.get("equipment_owner") or "",
                    "support_info": norm.get("support info") or norm.get("support_info") or "",
                    "maintenance_notes": norm.get("notes") or norm.get("maintenance notes") or "",
                }
                try:
                    self.add_device(payload, allow_duplicate_ip=not skip_duplicates)
                    imported += 1
                except Exception as exc:
                    errors.append(f"Row {idx} ({hostname}/{ip}): {exc}")

        self.audit.record_event(
            operation="INVENTORY_CSV_IMPORT",
            new_value={"imported": imported, "skipped_duplicates": skipped_duplicates, "errors_count": len(errors)},
            detail=f"CSV import completed: {imported} imported, {skipped_duplicates} duplicates skipped",
        )
        return {
            "imported": imported,
            "skipped_duplicates": skipped_duplicates,
            "errors": errors,
        }

    def export_csv(self, file_path: str, devices: Optional[List[Dict[str, Any]]] = None) -> None:
        items = devices if devices is not None else self.list_devices(limit=5000)
        headers = [
            "Device ID", "Hostname", "Management IP", "MAC Address", "Vendor", "Model",
            "Serial Number", "Firmware Version", "Category", "Role", "Site",
            "Rack / Location", "Management Protocol", "SNMP Profile", "Status",
            "Discovery Source", "Group", "Tags", "Purchase Date", "Warranty Expiration",
            "Manufacturer", "Owner", "Support Info", "Maintenance Notes",
        ]
        with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for d in items:
                writer.writerow([
                    d.get("device_uid", ""),
                    d.get("hostname", ""),
                    d.get("management_ip", ""),
                    d.get("mac_address", ""),
                    d.get("vendor", ""),
                    d.get("model", ""),
                    d.get("serial_number", ""),
                    d.get("firmware_version", ""),
                    d.get("category", ""),
                    d.get("role", ""),
                    d.get("site_name", ""),
                    d.get("rack_location", ""),
                    d.get("management_protocol", ""),
                    d.get("snmp_profile", ""),
                    d.get("status", ""),
                    d.get("discovery_source", ""),
                    d.get("device_group", ""),
                    ";".join(d.get("tags") or []),
                    d.get("purchase_date", ""),
                    d.get("warranty_expiration", ""),
                    d.get("manufacturer", ""),
                    d.get("equipment_owner", ""),
                    d.get("support_info", ""),
                    d.get("maintenance_notes", ""),
                ])

    def export_pdf(
        self,
        file_path: str,
        devices: Optional[List[Dict[str, Any]]] = None,
        title: str = "Rapport d'Inventaire Infrastructure",
    ) -> Tuple[bool, str]:
        items = devices if devices is not None else self.list_devices(limit=5000)
        from utils.pdf_generator import PDFReportGenerator
        return PDFReportGenerator().generate_inventory_report(items, save_path=file_path, title=title)
