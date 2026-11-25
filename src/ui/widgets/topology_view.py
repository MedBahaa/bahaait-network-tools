import asyncio
import math
from typing import Any, Dict, List, Optional, Set, Tuple

from PySide6.QtCore import QPointF, QRectF, Qt, QThread, QTimer, Signal
from PySide6.QtGui import (
    QAction,
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPainterPathStroker,
    QPen,
    QPixmap,
    QPolygonF,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.inventory_manager import DEVICE_CATEGORIES, InventoryManager
from core.site_manager import SiteManager
from core.topology_discovery import (
    TopologyDiscoveryEngine,
    _is_valid_probe_ip,
    _probe_hosts_concurrently,
)
from core.topology_graph import (
    STATUS_COLOR_MAP,
    VIEW_MODES,
    TopologyGraphService,
    orient_topology_hierarchy,
    resolve_status_color,
)
from utils.db import DatabaseManager, InfrastructureDevice, InfrastructureVlan, NetworkSite
from utils.i18n import _


class TopologyDiscoveryWorker(QThread):
    """Runs persistent multi-source discovery and live reachability verification off the UI thread."""

    finished_discovery = Signal(dict)
    failed = Signal(str)

    def __init__(self, db_path: Optional[str] = None, site_id: Optional[int] = None) -> None:
        super().__init__()
        self.db_path = db_path
        self.site_id = site_id
        self._cancel = False

    def request_stop(self) -> None:
        self._cancel = True

    def run(self) -> None:
        try:
            db = DatabaseManager(self.db_path) if self.db_path else DatabaseManager()
            if self._cancel:
                return
            engine = TopologyDiscoveryEngine(db)
            summary = asyncio.run(
                engine.discover_topology(
                    include_local_arp=True,
                    site_id=self.site_id,
                    probe_icmp=True,
                    resolve_hostnames=True,
                )
            )
            if not self._cancel:
                self.finished_discovery.emit(summary)
        except Exception as exc:
            if not self._cancel:
                self.failed.emit(str(exc))


class TopologyLiveDiscoveryWorker(QThread):
    """Runs live current-network-only discovery (active sweep, ARP, gateway & reachable SNMP) off UI thread."""

    finished_live = Signal(dict)
    failed = Signal(str)

    def __init__(self, db_path: Optional[str] = None) -> None:
        super().__init__()
        self.db_path = db_path
        self._cancel = False

    def request_stop(self) -> None:
        self._cancel = True

    def run(self) -> None:
        try:
            db = DatabaseManager(self.db_path) if self.db_path else DatabaseManager()
            if self._cancel:
                return
            engine = TopologyDiscoveryEngine(db)
            payload = asyncio.run(
                engine.discover_live_local_network(
                    active_sweep=True,
                    include_snmp=True,
                    resolve_hostnames=True,
                )
            )
            if not self._cancel:
                self.finished_live.emit(payload)
        except Exception as exc:
            if not self._cancel:
                self.failed.emit(str(exc))


class TopologyStatusWorker(QThread):
    """Refreshes live ICMP/TCP reachability statuses for mapped or live topology nodes off the UI thread."""

    finished_status = Signal(dict)
    finished_live_probes = Signal(dict)
    failed = Signal(str)

    def __init__(
        self,
        db_path: Optional[str] = None,
        site_id: Optional[int] = None,
        live_ips: Optional[List[str]] = None,
    ) -> None:
        super().__init__()
        self.db_path = db_path
        self.site_id = site_id
        self.live_ips = list(live_ips) if live_ips is not None else None
        self._cancel = False

    def request_stop(self) -> None:
        self._cancel = True

    def run(self) -> None:
        try:
            if self.live_ips is not None:
                probed = _probe_hosts_concurrently(self.live_ips)
                if not self._cancel:
                    self.finished_live_probes.emit(probed)
                return
            db = DatabaseManager(self.db_path) if self.db_path else DatabaseManager()
            if self._cancel:
                return
            counts = TopologyDiscoveryEngine(db).refresh_live_statuses(site_id=self.site_id)
            if not self._cancel:
                self.finished_status.emit(counts)
        except Exception as exc:
            if not self._cancel:
                self.failed.emit(str(exc))


class AssignToSiteDialog(QDialog):
    """Modal dialog to assign 1 or N discovered topology devices to an existing or newly created Site."""

    def __init__(
        self,
        devices: List[Dict[str, Any]],
        site_manager: SiteManager,
        default_gateway: str = "",
        subnet_cidr: str = "",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.devices = list(devices)
        self.site_manager = site_manager
        self.default_gateway = str(default_gateway or "").strip()
        self.subnet_cidr = str(subnet_cidr or "").strip()
        self._single_mode = len(self.devices) == 1

        self.setWindowTitle(_("topo_dlg_assign_title", "Add to Infrastructure Site"))
        self.setMinimumSize(520, 540)
        self.resize(560, 610)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        body = QWidget()
        body_l = QVBoxLayout(body)
        body_l.setContentsMargins(0, 0, 6, 0)
        body_l.setSpacing(12)

        # Device preview / editing card
        dev_card = QFrame()
        dev_card.setObjectName("PanelCard")
        dev_l = QFormLayout(dev_card)
        dev_l.setContentsMargins(14, 12, 14, 12)
        dev_l.setSpacing(8)

        self.hostname_edit: Optional[QLineEdit] = None
        self.category_combo: Optional[QComboBox] = None
        self.only_unassigned_chk: Optional[QCheckBox] = None

        if self._single_mode:
            d = self.devices[0]
            self.hostname_edit = QLineEdit(str(d.get("hostname") or ""))
            self.category_combo = QComboBox()
            for cat in DEVICE_CATEGORIES:
                self.category_combo.addItem(cat, cat)
            idx_cat = self.category_combo.findData(d.get("category") or "Other")
            if idx_cat >= 0:
                self.category_combo.setCurrentIndex(idx_cat)

            ip_lbl = QLabel(str(d.get("management_ip") or "-"))
            mac_lbl = QLabel(str(d.get("mac_address") or "-"))
            vend_lbl = QLabel(str(d.get("vendor") or "Unknown"))
            dev_l.addRow(_("inv_col_host", "Hostname:"), self.hostname_edit)
            dev_l.addRow(_("topo_col_ip", "IP Address:"), ip_lbl)
            dev_l.addRow(_("topo_col_mac", "MAC:"), mac_lbl)
            dev_l.addRow(_("inv_col_vendor", "Vendor:"), vend_lbl)
            dev_l.addRow(_("inv_col_cat", "Category:"), self.category_combo)
        else:
            unassigned_cnt = sum(1 for d in self.devices if not d.get("site_id"))
            summary_txt = _(
                "topo_dlg_summary",
                "{total} device(s) discovered ({unassigned} unassigned)",
            ).format(total=len(self.devices), unassigned=unassigned_cnt)
            if self.default_gateway or self.subnet_cidr:
                summary_txt += "\n" + _(
                    "topo_dlg_gw_subnet",
                    "Gateway: {gw} | Subnet: {cidr}",
                ).format(gw=self.default_gateway or "-", cidr=self.subnet_cidr or "-")
            sum_lbl = QLabel(summary_txt)
            sum_lbl.setWordWrap(True)
            sum_lbl.setStyleSheet("color: #E2E8F0; font-weight: 600;")
            dev_l.addRow(sum_lbl)
            self.only_unassigned_chk = QCheckBox(
                _("topo_dlg_only_unassigned", "Only add devices not yet assigned to a site")
            )
            self.only_unassigned_chk.setChecked(unassigned_cnt > 0 and unassigned_cnt < len(self.devices))
            self.only_unassigned_chk.setVisible(unassigned_cnt < len(self.devices) and unassigned_cnt > 0)
            dev_l.addRow(self.only_unassigned_chk)

        body_l.addWidget(dev_card)

        # Destination Site selection card
        site_card = QFrame()
        site_card.setObjectName("PanelCard")
        site_l = QVBoxLayout(site_card)
        site_l.setContentsMargins(14, 12, 14, 12)
        site_l.setSpacing(10)

        sites = self.site_manager.list_sites()
        self.radio_existing = QRadioButton(_("topo_dlg_existing_site", "Assign to an existing site"))
        self.site_combo = QComboBox()
        for s in sites:
            self.site_combo.addItem(f"{s['name']} ({s['organization']} / {s['region']})", s["id"])
        if self._single_mode and self.devices[0].get("site_id") is not None:
            cur_idx = self.site_combo.findData(self.devices[0]["site_id"])
            if cur_idx >= 0:
                self.site_combo.setCurrentIndex(cur_idx)

        self.radio_new = QRadioButton(_("topo_dlg_new_site", "Create a new site"))

        site_l.addWidget(self.radio_existing)
        site_l.addWidget(self.site_combo)
        site_l.addWidget(self.radio_new)

        new_form = QFormLayout()
        new_form.setContentsMargins(18, 4, 0, 4)
        new_form.setSpacing(8)
        default_site_name = f"Site {self.subnet_cidr}" if self.subnet_cidr else "New Client Site"
        self.new_name_edit = QLineEdit()
        self.new_name_edit.setPlaceholderText(default_site_name)
        self.new_org_edit = QLineEdit("Default Organization")
        self.new_region_edit = QLineEdit("Default Region")
        self.new_gw_edit = QLineEdit(self.default_gateway)
        self.new_cidr_edit = QLineEdit(self.subnet_cidr)

        new_form.addRow(_("topo_dlg_site_name", "Site Name *:"), self.new_name_edit)
        new_form.addRow(_("topo_dlg_org", "Organization:"), self.new_org_edit)
        new_form.addRow(_("topo_dlg_region", "Region:"), self.new_region_edit)
        new_form.addRow(_("topo_dlg_gateway", "Default Gateway:"), self.new_gw_edit)
        new_form.addRow(_("topo_dlg_cidr", "Network CIDR:"), self.new_cidr_edit)
        self._new_fields_widget = QWidget()
        self._new_fields_widget.setLayout(new_form)
        site_l.addWidget(self._new_fields_widget)

        self.save_links_chk = QCheckBox(_("topo_dlg_save_links", "Save discovered topology links into database"))
        self.save_links_chk.setChecked(True)
        site_l.addWidget(self.save_links_chk)

        body_l.addWidget(site_card)
        body_l.addStretch()

        scroll.setWidget(body)
        root.addWidget(scroll, 1)

        if sites:
            self.radio_existing.setChecked(True)
        else:
            self.radio_existing.setEnabled(False)
            self.radio_new.setChecked(True)
            self.new_name_edit.setText(default_site_name)

        self.radio_existing.toggled.connect(self._sync_mode)
        self.radio_new.toggled.connect(self._sync_mode)
        self._sync_mode()

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._on_accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    def _sync_mode(self) -> None:
        use_existing = self.radio_existing.isChecked() and self.radio_existing.isEnabled()
        self.site_combo.setEnabled(use_existing)
        self._new_fields_widget.setEnabled(not use_existing)

    def _on_accept(self) -> None:
        if self.radio_new.isChecked() or not self.radio_existing.isEnabled():
            if not self.new_name_edit.text().strip():
                QMessageBox.warning(self, _("common_error", "Error"), _("sites_err_name", "Site name is required."))
                return
        elif self.site_combo.currentData() is None:
            QMessageBox.warning(self, _("common_error", "Error"), _("sites_err_name", "Please select a site."))
            return
        self.accept()

    def get_result(self) -> Dict[str, Any]:
        use_new = self.radio_new.isChecked() or not self.radio_existing.isEnabled()
        target_devices = list(self.devices)
        if not self._single_mode and self.only_unassigned_chk is not None and self.only_unassigned_chk.isChecked():
            filtered = [d for d in target_devices if not d.get("site_id")]
            if filtered:
                target_devices = filtered

        new_site_data: Optional[Dict[str, Any]] = None
        site_id: Optional[int] = None
        if use_new:
            cidr_txt = self.new_cidr_edit.text().strip()
            new_site_data = {
                "name": self.new_name_edit.text().strip(),
                "organization": self.new_org_edit.text().strip() or "Default Organization",
                "region": self.new_region_edit.text().strip() or "Default Region",
                "default_gateway": self.new_gw_edit.text().strip(),
                "network_ranges": [r.strip() for r in cidr_txt.split(",") if r.strip()],
                "connectivity_mode": "LOCAL",
            }
        else:
            site_id = int(self.site_combo.currentData())

        return {
            "devices": target_devices,
            "site_id": site_id,
            "new_site_data": new_site_data,
            "save_links": bool(self.save_links_chk.isChecked()),
            "hostname_override": self.hostname_edit.text().strip() if self.hostname_edit is not None else None,
            "category_override": self.category_combo.currentData() if self.category_combo is not None else None,
        }


def _draw_device_vector_icon(
    painter: QPainter,
    rect: QRectF,
    category: str,
    is_gateway: bool,
    is_local_host: bool,
    color: QColor,
) -> None:
    """Draw a crisp TP-Link Omada / Ubiquiti UniFi style vector hardware glyph."""
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing, True)
    pen = QPen(color, 1.65, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)

    cx = rect.center().x()
    cy = rect.center().y()
    w = rect.width()
    h = rect.height()
    cat = (category or "").lower()

    if is_gateway or "router" in cat:
        r = min(w, h) * 0.43
        painter.drawEllipse(QPointF(cx, cy), r, r)
        # 4 directional router arrows
        d = r * 0.62
        painter.drawLine(QPointF(cx - d, cy), QPointF(cx + d, cy))
        painter.drawLine(QPointF(cx, cy - d), QPointF(cx, cy + d))
        painter.drawLine(QPointF(cx + d * 0.4, cy - d * 0.35), QPointF(cx + d, cy))
        painter.drawLine(QPointF(cx + d * 0.4, cy + d * 0.35), QPointF(cx + d, cy))
        painter.drawLine(QPointF(cx - d * 0.35, cy - d * 0.4), QPointF(cx, cy - d))
        painter.drawLine(QPointF(cx + d * 0.35, cy - d * 0.4), QPointF(cx, cy - d))
    elif "firewall" in cat:
        shield = QPainterPath()
        top_y = rect.top() + 1.5
        bot_y = rect.bottom() - 1.0
        shield.moveTo(cx, top_y)
        shield.lineTo(rect.right() - 2.0, top_y + h * 0.22)
        shield.quadTo(rect.right() - 2.5, cy + h * 0.18, cx, bot_y)
        shield.quadTo(rect.left() + 2.5, cy + h * 0.18, rect.left() + 2.0, top_y + h * 0.22)
        shield.closeSubpath()
        painter.drawPath(shield)
        painter.drawLine(QPointF(cx - w * 0.22, cy - 1.0), QPointF(cx + w * 0.22, cy - 1.0))
        painter.drawLine(QPointF(cx, cy - 4.0), QPointF(cx, cy + 4.0))
    elif "switch" in cat:
        box = QRectF(rect.left() + 1.0, cy - h * 0.24, w - 2.0, h * 0.48)
        painter.drawRoundedRect(box, 2.5, 2.5)
        # Port LEDs along lower half of 1U switch chassis
        painter.setBrush(QBrush(color))
        painter.setPen(Qt.NoPen)
        port_w = 2.6
        gap = (box.width() - 6.0 - 4 * port_w) / 3.0
        for i in range(4):
            px = box.left() + 3.0 + i * (port_w + gap)
            painter.drawRect(QRectF(px, box.bottom() - 4.5, port_w, 2.5))
        # Opposing switching arrows inside upper half
        painter.setPen(QPen(color, 1.3, Qt.SolidLine, Qt.RoundCap))
        painter.drawLine(QPointF(box.left() + 4.0, box.top() + 3.5), QPointF(box.right() - 4.0, box.top() + 3.5))
    elif "wireless" in cat or "controller" in cat or "ap" in cat:
        # Concentric Wi-Fi arcs + core dot
        painter.setBrush(QBrush(color))
        painter.drawEllipse(QPointF(cx, rect.bottom() - 4.5), 2.0, 2.0)
        painter.setBrush(Qt.NoBrush)
        for rad in (h * 0.34, h * 0.62):
            arc_r = QRectF(cx - rad, rect.bottom() - 4.5 - rad, rad * 2.0, rad * 2.0)
            painter.drawArc(arc_r, 40 * 16, 100 * 16)
    elif "server" in cat:
        for idx in (0, 1):
            y0 = rect.top() + 2.5 + idx * (h * 0.44)
            u_rect = QRectF(rect.left() + 2.0, y0, w - 4.0, h * 0.34)
            painter.drawRoundedRect(u_rect, 2.0, 2.0)
            painter.setBrush(QBrush(color))
            painter.drawEllipse(QPointF(u_rect.left() + 4.5, u_rect.center().y()), 1.4, 1.4)
            painter.setBrush(Qt.NoBrush)
    elif is_local_host:
        # Workstation monitor + base stand
        scr = QRectF(rect.left() + 1.5, rect.top() + 2.0, w - 3.0, h * 0.60)
        painter.drawRoundedRect(scr, 2.2, 2.2)
        painter.drawLine(QPointF(cx, scr.bottom()), QPointF(cx, rect.bottom() - 2.0))
        painter.drawLine(QPointF(cx - w * 0.25, rect.bottom() - 2.0), QPointF(cx + w * 0.25, rect.bottom() - 2.0))
    elif "printer" in cat:
        body = QRectF(rect.left() + 1.5, cy - 3.0, w - 3.0, h * 0.44)
        painter.drawRoundedRect(body, 2.0, 2.0)
        painter.drawRect(QRectF(cx - w * 0.24, rect.top() + 2.0, w * 0.48, h * 0.24))
    elif "ups" in cat:
        batt = QRectF(cx - w * 0.26, rect.top() + 2.5, w * 0.52, h - 4.5)
        painter.drawRoundedRect(batt, 2.2, 2.2)
        bolt = QPolygonF([
            QPointF(cx + 1.5, batt.top() + 3.5),
            QPointF(cx - 2.5, cy + 0.5),
            QPointF(cx + 0.5, cy + 0.5),
            QPointF(cx - 1.5, batt.bottom() - 3.5),
        ])
        painter.drawPolyline(bolt)
    else:
        # Clean endpoint node glyph
        r = min(w, h) * 0.28
        painter.drawEllipse(QPointF(cx, cy - 2.5), r * 0.72, r * 0.72)
        painter.drawArc(QRectF(cx - w * 0.32, cy + 1.0, w * 0.64, h * 0.50), 0, 180 * 16)

    painter.restore()


class TopologyEdgeItem(QGraphicsPathItem):
    """Omada/UniFi directional Bezier curve connecting Upstream -> Downstream devices."""

    def __init__(
        self,
        edge_data: Dict[str, Any],
        src_item: "TopologyNodeItem",
        dst_item: "TopologyNodeItem",
        offset_idx: int = 0,
        show_badge: bool = True,
    ) -> None:
        super().__init__()
        self.edge_data = edge_data
        self.src_item = src_item
        self.dst_item = dst_item
        self.offset_idx = offset_idx
        self.show_badge = show_badge
        self._hovered = False
        self._start_pt = QPointF()
        self._end_pt = QPointF()
        self._arrow_poly = QPolygonF()

        self.setZValue(1)
        self.setAcceptHoverEvents(True)

        src_name = src_item.node_data.get("hostname", "")
        dst_name = dst_item.node_data.get("hostname", "")
        src_if = edge_data.get("source_interface") or "?"
        dst_if = edge_data.get("dest_interface") or "?"
        ltype = edge_data.get("link_type") or "PHYSICAL"
        method = edge_data.get("discovery_method") or ""
        conf = edge_data.get("confidence") or ""
        vlans = edge_data.get("vlan_ids") or []
        ev = edge_data.get("evidence") or []
        tip_lines = [
            f"{ltype} ({method} / {conf})",
            f"{src_name}:{src_if} -> {dst_name}:{dst_if}",
        ]
        if vlans:
            tip_lines.append(f"VLANs: {', '.join(str(v) for v in vlans[:12])}")
        if ev:
            tip_lines.append(str(ev[0]))
        self.setToolTip("\n".join(tip_lines))

        self._line_color, self._pen_style, self._base_width = self._resolve_style()
        self._apply_pen()
        self.update_positions()

    def _resolve_style(self) -> Tuple[QColor, Qt.PenStyle, float]:
        status = str(self.edge_data.get("status") or "UP").upper()
        ltype = str(self.edge_data.get("link_type") or "PHYSICAL").upper()
        method = str(self.edge_data.get("discovery_method") or "").upper()

        if ltype == "INTER_SITE":
            color, style, width = QColor("#06B6D4"), Qt.DashLine, 2.0
        elif "VLAN" in ltype:
            color, style, width = QColor("#818CF8"), Qt.SolidLine, 2.0
        elif ltype == "LOGICAL":
            color, style, width = QColor("#818CF8"), Qt.DashLine, 1.9
        elif ltype == "GATEWAY_UPLINK" or method == "GATEWAY_ARP":
            color, style, width = QColor("#2DD4BF"), Qt.DashLine, 1.8
        elif method in ("LLDP", "CDP") or ltype in ("UPLINK", "AP_UPLINK"):
            color, style, width = QColor("#38BDF8"), Qt.SolidLine, 2.2
        else:
            color, style, width = QColor("#60A5FA"), Qt.SolidLine, 2.0

        if status in ("DOWN", "OFFLINE", "CRITICAL"):
            color = QColor(STATUS_COLOR_MAP["DOWN"])
        elif status in ("DEGRADED", "WARNING"):
            color = QColor(STATUS_COLOR_MAP["DEGRADED"])
        if self.edge_data.get("confidence") == "LOW":
            style = Qt.DotLine

        return color, style, width

    def _apply_pen(self) -> None:
        w = (self._base_width + 1.1) if self._hovered else self._base_width
        pen = QPen(self._line_color, w, self._pen_style, Qt.RoundCap, Qt.RoundJoin)
        if self._pen_style == Qt.DashLine:
            pen.setDashPattern([6.0, 4.0])
        self.setPen(pen)

    def _badge_text(self) -> str:
        ltype = str(self.edge_data.get("link_type") or "").upper()
        method = str(self.edge_data.get("discovery_method") or "").upper()
        src_if = str(self.edge_data.get("source_interface") or "").strip()
        dst_if = str(self.edge_data.get("dest_interface") or "").strip()
        if method == "GATEWAY_ARP" or ltype == "GATEWAY_UPLINK":
            return "GW -> LAN"
        if ltype == "INTER_SITE":
            return "WAN"
        if src_if and dst_if:
            txt = f"{src_if} -> {dst_if}"
            return txt if len(txt) <= 22 else f"{src_if[:9]}..{dst_if[:9]}"
        return method or ltype[:8]

    def boundingRect(self) -> QRectF:
        return super().boundingRect().adjusted(-68.0, -24.0, 68.0, 24.0)

    def shape(self) -> QPainterPath:
        stroker = QPainterPathStroker()
        stroker.setWidth(12.0)
        return stroker.createStroke(self.path())

    def hoverEnterEvent(self, event) -> None:
        self._hovered = True
        self._apply_pen()
        self.setZValue(3)
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event) -> None:
        self._hovered = False
        self._apply_pen()
        self.setZValue(1)
        self.update()
        super().hoverLeaveEvent(event)

    def update_positions(self) -> None:
        c1 = self.src_item.center_pos()
        c2 = self.dst_item.center_pos()
        dx = c2.x() - c1.x()
        dy = c2.y() - c1.y()
        shift = (22.0 if self.offset_idx % 2 == 1 else -22.0) * ((self.offset_idx + 1) // 2) if self.offset_idx > 0 else 0.0

        path = QPainterPath()
        if abs(dy) >= abs(dx) * 0.42:
            if dy >= 0:
                start = self.src_item.bottom_port_pos()
                end = self.dst_item.top_port_pos()
                side = 1.0
            else:
                start = self.src_item.top_port_pos()
                end = self.dst_item.bottom_port_pos()
                side = -1.0
            span = max(34.0, abs(end.y() - start.y()) * 0.48)
            ctrl1 = QPointF(start.x() + shift, start.y() + span * side)
            ctrl2 = QPointF(end.x() + shift, end.y() - span * side)
        else:
            if dx >= 0:
                start = self.src_item.right_port_pos()
                end = self.dst_item.left_port_pos()
                side = 1.0
            else:
                start = self.src_item.left_port_pos()
                end = self.dst_item.right_port_pos()
                side = -1.0
            span = max(34.0, abs(end.x() - start.x()) * 0.46)
            ctrl1 = QPointF(start.x() + span * side, start.y() + shift)
            ctrl2 = QPointF(end.x() - span * side, end.y() + shift)

        path.moveTo(start)
        path.cubicTo(ctrl1, ctrl2, end)
        self._start_pt = start
        self._end_pt = end

        # Build crisp arrowhead aligned strictly along incoming curve tangent into end
        near_pt = path.pointAtPercent(0.95)
        vx = end.x() - near_pt.x()
        vy = end.y() - near_pt.y()
        vlen = math.hypot(vx, vy)
        if vlen < 1e-3:
            vx, vy = dx, dy
            vlen = math.hypot(vx, vy) or 1.0
        ux, uy = vx / vlen, vy / vlen
        px, py = -uy, ux
        arr_len = 9.5
        arr_w = 4.6
        w1 = QPointF(end.x() - ux * arr_len + px * arr_w, end.y() - uy * arr_len + py * arr_w)
        w2 = QPointF(end.x() - ux * arr_len - px * arr_w, end.y() - uy * arr_len - py * arr_w)
        self._arrow_poly = QPolygonF([end, w1, w2])

        self.setPath(path)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        painter.setRenderHint(QPainter.Antialiasing, True)
        p = self.path()
        if self._hovered:
            glow_pen = QPen(QColor(self._line_color.red(), self._line_color.green(), self._line_color.blue(), 65), 7.5, Qt.SolidLine, Qt.RoundCap)
            painter.setPen(glow_pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawPath(p)

        painter.setPen(self.pen())
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(p)

        # Source terminal dot
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(self._line_color))
        painter.drawEllipse(self._start_pt, 2.8, 2.8)

        # Directional arrowhead pointing into downstream device
        if not self._arrow_poly.isEmpty():
            painter.drawPolygon(self._arrow_poly)

        # Compact link label pill (always on hover, or on direct non-fanout infrastructure links)
        is_gw_fanout = str(self.edge_data.get("discovery_method") or "").upper() == "GATEWAY_ARP" and not self._hovered
        if (self._hovered or self.show_badge) and not is_gw_fanout:
            mid = p.pointAtPercent(0.5)
            txt = self._badge_text()
            if txt:
                bfont = QFont("Segoe UI", 7.0, QFont.DemiBold)
                fm = QFontMetrics(bfont)
                tw = fm.horizontalAdvance(txt) + 12.0
                th = 16.0
                pill = QRectF(mid.x() - tw / 2.0, mid.y() - th / 2.0, tw, th)
                painter.setBrush(QBrush(QColor(11, 18, 32, 232)))
                painter.setPen(QPen(self._line_color, 1.0))
                painter.drawRoundedRect(pill, 7.0, 7.0)
                painter.setFont(bfont)
                painter.setPen(QColor("#E2E8F0"))
                painter.drawText(pill, Qt.AlignCenter, txt)


class TopologyNodeItem(QGraphicsObject):
    """TP-Link Omada / Ubiquiti UniFi style interactive hardware card with WAN/Gateway/Flow indicators."""

    moved = Signal(int, float, float)
    clicked = Signal(dict)
    context_action = Signal(str, dict)

    WIDTH = 212.0
    HEIGHT = 96.0

    def __init__(self, node_data: Dict[str, Any]) -> None:
        super().__init__()
        self.node_data = node_data
        self.edges: List[TopologyEdgeItem] = []
        self._hovered = False

        self.setFlags(
            QGraphicsItem.ItemIsMovable
            | QGraphicsItem.ItemIsSelectable
            | QGraphicsItem.ItemSendsGeometryChanges
        )
        self.setAcceptHoverEvents(True)
        self.setZValue(2)
        self._update_tooltip()

    def _update_tooltip(self) -> None:
        d = self.node_data
        up_host = d.get("upstream_hostname") or "-"
        up_port = d.get("upstream_port") or ""
        up_txt = f"{up_host} ({up_port})" if up_port else up_host
        dn_cnt = int(d.get("downstream_count") or 0)
        lat = d.get("latency_ms")
        lat_txt = f" ({lat:.1f} ms)" if isinstance(lat, (int, float)) else ""
        self.setToolTip(
            f"{d.get('hostname', '')}\n"
            f"IP: {d.get('management_ip', '-')} | MAC: {d.get('mac_address') or '-'}\n"
            f"Vendor: {d.get('vendor', 'Unknown')} | Type: {d.get('category', 'Other')}\n"
            f"Site: {d.get('site_name', 'Unassigned')}\n"
            f"Status: {d.get('status', 'UNKNOWN')}{lat_txt}\n"
            f"Uplink: {up_txt} | Downstream: {dn_cnt}"
        )

    def boundingRect(self) -> QRectF:
        return QRectF(-10.0, -38.0, self.WIDTH + 20.0, self.HEIGHT + 46.0)

    def shape(self) -> QPainterPath:
        p = QPainterPath()
        p.addRoundedRect(QRectF(0.0, 0.0, self.WIDTH, self.HEIGHT), 10.0, 10.0)
        if self.node_data.get("is_gateway"):
            p.addRoundedRect(QRectF(48.0, -32.0, 108.0, 20.0), 8.0, 8.0)
        return p

    def center_pos(self) -> QPointF:
        return self.pos() + QPointF(self.WIDTH / 2.0, self.HEIGHT / 2.0)

    def top_port_pos(self) -> QPointF:
        return self.pos() + QPointF(self.WIDTH / 2.0, 0.0)

    def bottom_port_pos(self) -> QPointF:
        return self.pos() + QPointF(self.WIDTH / 2.0, self.HEIGHT)

    def left_port_pos(self) -> QPointF:
        return self.pos() + QPointF(0.0, self.HEIGHT / 2.0)

    def right_port_pos(self) -> QPointF:
        return self.pos() + QPointF(self.WIDTH, self.HEIGHT / 2.0)

    def attach_edge(self, edge: TopologyEdgeItem) -> None:
        self.edges.append(edge)

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value: Any) -> Any:
        if change == QGraphicsItem.ItemPositionHasChanged:
            for e in self.edges:
                e.update_positions()
            pos = self.pos()
            self.moved.emit(int(self.node_data["id"]), float(pos.x()), float(pos.y()))
        elif change == QGraphicsItem.ItemSelectedHasChanged:
            self.update()
        return super().itemChange(change, value)

    def mousePressEvent(self, event) -> None:
        super().mousePressEvent(event)
        self.clicked.emit(self.node_data)

    def hoverEnterEvent(self, event) -> None:
        self._hovered = True
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event) -> None:
        self._hovered = False
        self.update()
        super().hoverLeaveEvent(event)

    def contextMenuEvent(self, event) -> None:
        self.setSelected(True)
        self.clicked.emit(self.node_data)

        menu = QMenu()
        menu.setStyleSheet(
            "QMenu { background-color: #161F30; color: #F8FAFC; border: 1px solid #334155; padding: 4px; }"
            "QMenu::item { padding: 6px 14px; border-radius: 4px; }"
            "QMenu::item:selected { background-color: #4F46E5; color: #FFFFFF; }"
            "QMenu::separator { height: 1px; background: #263348; margin: 4px 6px; }"
        )

        act_site = QAction(_("topo_ctx_add_site", "Add / Assign to Site..."), menu)
        is_gw = bool(self.node_data.get("is_gateway"))
        act_gw = QAction(
            _("topo_ctx_unset_gateway", "Unset Gateway Role")
            if is_gw
            else _("topo_ctx_set_gateway", "Set as Default Gateway"),
            menu,
        )
        menu.addAction(act_site)
        menu.addAction(act_gw)
        menu.addSeparator()

        has_ip = _is_valid_probe_ip(str(self.node_data.get("management_ip") or ""))
        act_acc = QAction(_("topo_btn_access", "Open in Access Center"), menu)
        act_acc.setEnabled(has_ip)
        act_web = QAction(_("topo_btn_web", "Web UI"), menu)
        act_web.setEnabled(has_ip)
        menu.addAction(act_acc)
        menu.addAction(act_web)
        menu.addSeparator()

        act_copy_ip = QAction(_("topo_ctx_copy_ip", "Copy IP Address"), menu)
        act_copy_ip.setEnabled(has_ip)
        has_mac = bool(self.node_data.get("mac_address"))
        act_copy_mac = QAction(_("topo_ctx_copy_mac", "Copy MAC Address"), menu)
        act_copy_mac.setEnabled(has_mac)
        menu.addAction(act_copy_ip)
        menu.addAction(act_copy_mac)

        chosen = menu.exec(event.screenPos())
        if chosen == act_site:
            self.context_action.emit("add_to_site", self.node_data)
        elif chosen == act_gw:
            self.context_action.emit("toggle_gateway", self.node_data)
        elif chosen == act_acc:
            self.context_action.emit("open_access", self.node_data)
        elif chosen == act_web:
            self.context_action.emit("open_web", self.node_data)
        elif chosen == act_copy_ip:
            self.context_action.emit("copy_ip", self.node_data)
        elif chosen == act_copy_mac:
            self.context_action.emit("copy_mac", self.node_data)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        painter.setRenderHint(QPainter.Antialiasing, True)
        selected = self.isSelected()
        d = self.node_data
        status = str(d.get("status") or "UNKNOWN").upper()
        is_gateway = bool(d.get("is_gateway"))
        is_local = bool(d.get("is_local_host"))
        status_hex = resolve_status_color(status, selected=False)
        status_col = QColor(status_hex)

        # Optional INTERNET / WAN uplink crown above Gateway card
        if is_gateway:
            wan_pill = QRectF(self.WIDTH / 2.0 - 54.0, -32.0, 108.0, 18.0)
            painter.setBrush(QBrush(QColor(15, 23, 42, 235)))
            painter.setPen(QPen(QColor("#2DD4BF"), 1.1))
            painter.drawRoundedRect(wan_pill, 9.0, 9.0)
            wfont = QFont("Segoe UI", 6.8, QFont.Bold)
            painter.setFont(wfont)
            painter.setPen(QColor("#2DD4BF"))
            painter.drawText(wan_pill, Qt.AlignCenter, "INTERNET / WAN")
            # Stem arrow down into gateway top port
            cx = self.WIDTH / 2.0
            painter.setPen(QPen(QColor("#2DD4BF"), 1.5))
            painter.drawLine(QPointF(cx, -14.0), QPointF(cx, 0.0))
            painter.setBrush(QBrush(QColor("#2DD4BF")))
            painter.setPen(Qt.NoPen)
            painter.drawPolygon(QPolygonF([QPointF(cx, 0.0), QPointF(cx - 3.5, -5.0), QPointF(cx + 3.5, -5.0)]))

        card_rect = QRectF(0.0, 0.0, self.WIDTH, self.HEIGHT)

        # Selection glow halo
        if selected:
            painter.setBrush(Qt.NoBrush)
            painter.setPen(QPen(QColor(56, 189, 248, 85), 4.5))
            painter.drawRoundedRect(card_rect.adjusted(-2.5, -2.5, 2.5, 2.5), 12.0, 12.0)

        # Gradient chassis fill
        grad = QLinearGradient(0.0, 0.0, 0.0, self.HEIGHT)
        if selected:
            grad.setColorAt(0.0, QColor("#1B365D"))
            grad.setColorAt(1.0, QColor("#12233E"))
        elif self._hovered:
            grad.setColorAt(0.0, QColor("#213049"))
            grad.setColorAt(1.0, QColor("#152033"))
        else:
            grad.setColorAt(0.0, QColor("#182338"))
            grad.setColorAt(1.0, QColor("#111827"))

        if selected:
            b_col, b_w = QColor("#38BDF8"), 2.0
        elif is_gateway:
            b_col, b_w = QColor("#F59E0B"), 1.6
        elif is_local:
            b_col, b_w = QColor("#06B6D4"), 1.4
        elif self._hovered:
            b_col, b_w = QColor("#64748B"), 1.4
        else:
            b_col, b_w = QColor("#2A3950"), 1.1

        painter.setBrush(QBrush(grad))
        painter.setPen(QPen(b_col, b_w))
        painter.drawRoundedRect(card_rect, 10.0, 10.0)

        # Top slim status accent bar clipped inside top rounded corners
        painter.save()
        clip_path = QPainterPath()
        clip_path.addRoundedRect(card_rect, 10.0, 10.0)
        painter.setClipPath(clip_path)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(status_col))
        painter.drawRect(QRectF(0.0, 0.0, self.WIDTH, 3.0))
        painter.restore()

        # Left hardware icon badge
        role_color = QColor("#F59E0B") if is_gateway else (QColor("#06B6D4") if is_local else status_col)
        icon_box = QRectF(11.0, 13.0, 38.0, 38.0)
        painter.setBrush(QBrush(QColor(role_color.red(), role_color.green(), role_color.blue(), 26)))
        painter.setPen(QPen(QColor(role_color.red(), role_color.green(), role_color.blue(), 110), 1.0))
        painter.drawRoundedRect(icon_box, 8.0, 8.0)
        _draw_device_vector_icon(
            painter,
            icon_box.adjusted(7.0, 7.0, -7.0, -7.0),
            str(d.get("category") or "Other"),
            is_gateway,
            is_local,
            role_color,
        )

        # Top-right compact Status / Latency pill
        lat = d.get("latency_ms")
        if status in ("ONLINE", "UP", "OK"):
            st_txt = f"{lat:.0f}ms" if isinstance(lat, (int, float)) else "ON"
        elif status in ("DEGRADED", "WARNING", "RECOVERING"):
            st_txt = f"{lat:.0f}ms" if isinstance(lat, (int, float)) else "DEG"
        elif status in ("DOWN", "OFFLINE", "CRITICAL"):
            st_txt = "OFF"
        else:
            st_txt = "?"

        pfont = QFont("Segoe UI", 6.8, QFont.Bold)
        pfm = QFontMetrics(pfont)
        pw = max(32.0, min(54.0, float(pfm.horizontalAdvance(st_txt)) + 16.0))
        spill = QRectF(self.WIDTH - pw - 10.0, 10.0, pw, 17.0)
        painter.setBrush(QBrush(QColor(status_col.red(), status_col.green(), status_col.blue(), 28)))
        painter.setPen(QPen(QColor(status_col.red(), status_col.green(), status_col.blue(), 130), 0.9))
        painter.drawRoundedRect(spill, 8.5, 8.5)
        painter.setBrush(QBrush(status_col))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(spill.left() + 6.5, spill.center().y()), 2.6, 2.6)
        painter.setFont(pfont)
        painter.setPen(QColor("#F8FAFC"))
        painter.drawText(spill.adjusted(10.0, 0.0, -4.0, 0.0), Qt.AlignVCenter | Qt.AlignCenter, st_txt)

        # Hostname, IP, Vendor + Category text stack
        text_x = 57.0
        host_w = spill.left() - text_x - 6.0
        tfont = QFont("Segoe UI", 8.6, QFont.Bold)
        painter.setFont(tfont)
        painter.setPen(QColor("#F8FAFC"))
        host_elided = QFontMetrics(tfont).elidedText(str(d.get("hostname") or "Unknown"), Qt.ElideRight, int(max(40, host_w)))
        painter.drawText(QRectF(text_x, 9.0, max(40.0, host_w), 18.0), Qt.AlignVCenter | Qt.AlignLeft, host_elided)

        ipfont = QFont("Consolas", 8.0)
        painter.setFont(ipfont)
        painter.setPen(QColor("#38BDF8"))
        ip_elided = QFontMetrics(ipfont).elidedText(str(d.get("management_ip") or "-"), Qt.ElideRight, int(self.WIDTH - text_x - 10))
        painter.drawText(QRectF(text_x, 28.0, self.WIDTH - text_x - 10.0, 15.0), Qt.AlignVCenter | Qt.AlignLeft, ip_elided)

        vfont = QFont("Segoe UI", 7.2)
        painter.setFont(vfont)
        painter.setPen(QColor("#94A3B8"))
        vend = str(d.get("vendor") or "Unknown")
        cat = str(d.get("category") or "Other")
        meta_str = f"{vend} · {cat}" if vend != "Unknown" else cat
        meta_elided = QFontMetrics(vfont).elidedText(meta_str, Qt.ElideRight, int(self.WIDTH - text_x - 10))
        painter.drawText(QRectF(text_x, 44.0, self.WIDTH - text_x - 10.0, 15.0), Qt.AlignVCenter | Qt.AlignLeft, meta_elided)

        # Hairline divider above footer
        painter.setPen(QPen(QColor("#1E293B"), 1.0))
        painter.drawLine(QPointF(10.0, 65.5), QPointF(self.WIDTH - 10.0, 65.5))

        # Footer left badge (Gateway / Local PC / New Unassigned / Site Name)
        if is_gateway:
            b_txt = _("topo_badge_gateway", "GATEWAY")
            b_fg = QColor("#F59E0B")
            b_bg = QColor(245, 158, 11, 34)
        elif is_local:
            b_txt = _("topo_badge_local_pc", "THIS PC")
            b_fg = QColor("#06B6D4")
            b_bg = QColor(6, 182, 212, 34)
        elif d.get("site_id") is not None:
            b_txt = str(d.get("site_name") or "Site")
            b_fg = QColor("#CBD5E1")
            b_bg = QColor(51, 65, 85, 140)
        else:
            b_txt = _("topo_badge_new", "NEW")
            b_fg = QColor("#A5B4FC")
            b_bg = QColor(99, 102, 241, 40)

        bfont = QFont("Segoe UI", 6.6, QFont.Bold)
        bfm = QFontMetrics(bfont)
        b_max_w = max(72.0, self.WIDTH - 70.0)
        b_elided = bfm.elidedText(b_txt, Qt.ElideRight, int(b_max_w - 10.0))
        bw = min(b_max_w, float(bfm.horizontalAdvance(b_elided)) + 10.0)
        brect = QRectF(10.0, 71.0, bw, 18.0)
        painter.setBrush(QBrush(b_bg))
        painter.setPen(QPen(QColor(b_fg.red(), b_fg.green(), b_fg.blue(), 110), 0.9))
        painter.drawRoundedRect(brect, 5.0, 5.0)
        painter.setFont(bfont)
        painter.setPen(b_fg)
        painter.drawText(brect, Qt.AlignCenter, b_elided)

        # Secondary subtle +SITE tag next to PASSERELLE / CE PC when unassigned
        if (is_gateway or is_local) and d.get("site_id") is None:
            new_txt = "+SITE"
            new_w = float(bfm.horizontalAdvance(new_txt)) + 8.0
            new_x = brect.right() + 4.0
            if new_x + new_w <= self.WIDTH - 52.0:
                new_rect = QRectF(new_x, 71.0, new_w, 18.0)
                painter.setBrush(QBrush(QColor(99, 102, 241, 38)))
                painter.setPen(QPen(QColor(129, 140, 248, 110), 0.8))
                painter.drawRoundedRect(new_rect, 5.0, 5.0)
                painter.setPen(QColor("#A5B4FC"))
                painter.drawText(new_rect, Qt.AlignCenter, new_txt)

        # Footer right geometric vector Uplink / Downstream flow counters
        up_cnt = int(d.get("uplink_count") or 0)
        dn_cnt = int(d.get("downstream_count") or 0)
        ffont = QFont("Segoe UI", 7.2, QFont.DemiBold)
        ffm = QFontMetrics(ffont)
        dn_str = str(dn_cnt)
        up_str = str(up_cnt)
        dn_tw = float(ffm.horizontalAdvance(dn_str))
        up_tw = float(ffm.horizontalAdvance(up_str))

        dn_col = QColor("#38BDF8") if dn_cnt > 0 else QColor("#64748B")
        up_col = QColor("#2DD4BF") if up_cnt > 0 else QColor("#64748B")
        cy_f = 80.0

        # Draw Downlink count anchored on right edge
        dn_txt_x = self.WIDTH - 10.0 - dn_tw
        dn_tri_x = dn_txt_x - 8.5
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(dn_col))
        painter.drawPolygon(QPolygonF([
            QPointF(dn_tri_x, cy_f - 2.2),
            QPointF(dn_tri_x + 6.0, cy_f - 2.2),
            QPointF(dn_tri_x + 3.0, cy_f + 2.8),
        ]))
        painter.setFont(ffont)
        painter.setPen(dn_col)
        painter.drawText(QRectF(dn_txt_x, 71.0, dn_tw + 2.0, 18.0), Qt.AlignVCenter | Qt.AlignLeft, dn_str)

        # Draw Uplink count immediately to the left
        up_txt_x = dn_tri_x - 6.0 - up_tw
        up_tri_x = up_txt_x - 8.5
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(up_col))
        painter.drawPolygon(QPolygonF([
            QPointF(up_tri_x + 3.0, cy_f - 2.8),
            QPointF(up_tri_x, cy_f + 2.2),
            QPointF(up_tri_x + 6.0, cy_f + 2.2),
        ]))
        painter.setPen(up_col)
        painter.drawText(QRectF(up_txt_x, 71.0, up_tw + 2.0, 18.0), Qt.AlignVCenter | Qt.AlignLeft, up_str)


class TopologyCanvas(QGraphicsView):
    """Interactive pan/zoom QGraphicsView hosting Omada/UniFi hardware cards & directional links."""

    node_selected = Signal(dict)
    node_context_action = Signal(str, dict)
    canvas_cleared = Signal()
    layout_modified = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.scene_obj = QGraphicsScene(self)
        self.setScene(self.scene_obj)
        self.setRenderHint(QPainter.Antialiasing, True)
        self.setRenderHint(QPainter.TextAntialiasing, True)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setViewportUpdateMode(QGraphicsView.SmartViewportUpdate)
        self.setStyleSheet("QGraphicsView { background-color: #0A101D; border: 1px solid #1E293B; border-radius: 10px; }")

        self.node_items: Dict[int, TopologyNodeItem] = {}
        self.edge_items: List[TopologyEdgeItem] = []
        self._zoom_factor = 1.0
        self._suppress_move_signal = False

    def drawBackground(self, painter: QPainter, rect: QRectF) -> None:
        painter.fillRect(rect, QColor("#0A101D"))
        step = 28
        left = int(math.floor(rect.left() / step) * step)
        top = int(math.floor(rect.top() / step) * step)
        right = int(math.ceil(rect.right()))
        bottom = int(math.ceil(rect.bottom()))
        painter.setPen(QPen(QColor("#1E293B"), 1.6))
        pts: List[QPointF] = []
        x = left
        while x <= right:
            y = top
            while y <= bottom:
                pts.append(QPointF(float(x), float(y)))
                y += step
            x += step
        if pts and len(pts) <= 6000:
            painter.drawPoints(pts)

    def wheelEvent(self, event) -> None:
        delta = event.angleDelta().y()
        if delta == 0:
            super().wheelEvent(event)
            return
        factor = 1.15 if delta > 0 else 1.0 / 1.15
        self.apply_zoom_factor(factor)

    def apply_zoom_factor(self, factor: float) -> None:
        new_zoom = self._zoom_factor * factor
        if 0.2 <= new_zoom <= 3.5:
            self.scale(factor, factor)
            self._zoom_factor = new_zoom

    def set_zoom_level(self, zoom: float) -> None:
        zoom = max(0.2, min(3.5, float(zoom or 1.0)))
        self.resetTransform()
        self.scale(zoom, zoom)
        self._zoom_factor = zoom

    def fit_graph(self) -> None:
        rect = self.scene_obj.itemsBoundingRect()
        if not rect.isNull():
            padded = rect.adjusted(-60, -60, 60, 60)
            self.fitInView(padded, Qt.KeepAspectRatio)
            self._zoom_factor = max(0.2, min(3.5, self.transform().m11()))

    def populate_graph(
        self,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        positions: Dict[int, Tuple[float, float]],
    ) -> None:
        self._suppress_move_signal = True
        try:
            self.scene_obj.clear()
            self.node_items.clear()
            self.edge_items.clear()

            for n in nodes:
                item = TopologyNodeItem(n)
                pos = positions.get(int(n["id"]), (0.0, 0.0))
                item.setPos(float(pos[0]), float(pos[1]))
                item.clicked.connect(self.node_selected.emit)
                item.context_action.connect(self.node_context_action.emit)
                item.moved.connect(self._on_node_moved)
                self.scene_obj.addItem(item)
                self.node_items[int(n["id"])] = item

            pair_counts: Dict[Tuple[int, int], int] = {}
            show_badges = len(edges) <= 40
            for e in edges:
                sid = int(e["source_device_id"])
                did = int(e["dest_device_id"])
                s_item = self.node_items.get(sid)
                d_item = self.node_items.get(did)
                if not s_item or not d_item:
                    continue
                pair_key = (min(sid, did), max(sid, did))
                idx = pair_counts.get(pair_key, 0)
                pair_counts[pair_key] = idx + 1
                edge_item = TopologyEdgeItem(e, s_item, d_item, offset_idx=idx, show_badge=show_badges)
                s_item.attach_edge(edge_item)
                d_item.attach_edge(edge_item)
                self.scene_obj.addItem(edge_item)
                self.edge_items.append(edge_item)

            rect = self.scene_obj.itemsBoundingRect()
            if not rect.isNull():
                self.scene_obj.setSceneRect(rect.adjusted(-260, -260, 260, 260))
        finally:
            self._suppress_move_signal = False

    def _on_node_moved(self, _did: int, _x: float, _y: float) -> None:
        if not self._suppress_move_signal:
            self.layout_modified.emit()

    def current_positions(self) -> Dict[int, Tuple[float, float]]:
        return {
            did: (round(float(item.pos().x()), 1), round(float(item.pos().y()), 1))
            for did, item in self.node_items.items()
        }

    def apply_positions(self, positions: Dict[int, Tuple[float, float]]) -> None:
        self._suppress_move_signal = True
        try:
            for did, item in self.node_items.items():
                if did in positions:
                    item.setPos(float(positions[did][0]), float(positions[did][1]))
        finally:
            self._suppress_move_signal = False

    def mousePressEvent(self, event) -> None:
        super().mousePressEvent(event)
        if self.itemAt(event.pos()) is None:
            self.canvas_cleared.emit()

    def select_device(self, device_id: int) -> None:
        for did, item in self.node_items.items():
            matched = did == device_id
            item.setSelected(matched)
            if matched:
                self.centerOn(item)
                self.node_selected.emit(item.node_data)


class TopologyView(QWidget):
    """Network Topology Map view with Live Current-Network discovery, Pro Omada/UniFi cards, and Site onboarding."""

    open_in_access_center = Signal(dict)
    open_in_browser = Signal(str)
    inventory_updated = Signal()

    _LIVE_SCOPE_DATA = "__LIVE__"

    def __init__(self, db: Optional[DatabaseManager] = None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.db = db or DatabaseManager()
        self.graph_service = TopologyGraphService(self.db)
        self.site_manager = SiteManager(self.db)
        self._discovery_worker: Optional[TopologyDiscoveryWorker] = None
        self._live_worker: Optional[TopologyLiveDiscoveryWorker] = None
        self._status_worker: Optional[TopologyStatusWorker] = None
        self._current_graph: Dict[str, Any] = {"view_mode": "PHYSICAL", "nodes": [], "edges": []}
        self._selected_node: Optional[Dict[str, Any]] = None
        self._has_unsaved_layout = False
        self._view_scope = "SAVED"
        self._live_payload: Optional[Dict[str, Any]] = None
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(180)
        self._search_timer.timeout.connect(self.refresh)

        self._setup_ui()
        self.refresh()

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(10)

        # Header Row 1: Title + Subtitle
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_lbl = QLabel(_("topo_title", "Network Topology"))
        title_lbl.setObjectName("Title")
        title_lbl.setStyleSheet("font-size: 20px; font-weight: bold; color: #F8FAFC;")
        sub_lbl = QLabel(_("topo_subtitle", "Automatic multi-source mapping (LLDP, CDP, ARP, SNMP, Bridge MIB)"))
        sub_lbl.setWordWrap(True)
        sub_lbl.setStyleSheet("color: #94A3B8; font-size: 12px;")
        title_col.addWidget(title_lbl)
        title_col.addWidget(sub_lbl)
        root.addLayout(title_col)

        # Header Row 2: Action Toolbar
        hdr_btns = QHBoxLayout()
        hdr_btns.setSpacing(8)
        self.discover_btn = QPushButton(_("topo_btn_discover", "Discover Topology"))
        self.discover_btn.setObjectName("PrimaryButton")
        self.discover_btn.clicked.connect(self.start_discovery)
        hdr_btns.addWidget(self.discover_btn)

        self.check_status_btn = QPushButton(_("topo_btn_check_status", "Check Live Status"))
        self.check_status_btn.setObjectName("SecondaryButton")
        self.check_status_btn.clicked.connect(self.start_status_check)
        hdr_btns.addWidget(self.check_status_btn)

        self.auto_layout_btn = QPushButton(_("topo_btn_auto_layout", "Auto Layout"))
        self.auto_layout_btn.setObjectName("SecondaryButton")
        self.auto_layout_btn.clicked.connect(self.recompute_auto_layout)
        hdr_btns.addWidget(self.auto_layout_btn)

        self.save_layout_btn = QPushButton(_("topo_btn_save_layout", "Save Layout"))
        self.save_layout_btn.setObjectName("SecondaryButton")
        self.save_layout_btn.clicked.connect(self.save_current_layout)
        hdr_btns.addWidget(self.save_layout_btn)

        self.export_png_btn = QPushButton(_("topo_btn_export_png", "Export PNG"))
        self.export_png_btn.setObjectName("SecondaryButton")
        self.export_png_btn.clicked.connect(self.export_png)
        hdr_btns.addWidget(self.export_png_btn)

        for b in (self.discover_btn, self.check_status_btn, self.auto_layout_btn, self.save_layout_btn, self.export_png_btn):
            b.setCursor(Qt.PointingHandCursor)
            b.setToolTip(b.text())
        hdr_btns.addStretch()
        root.addLayout(hdr_btns)

        # Filter Toolbar
        bar = QFrame()
        bar.setObjectName("FilterBar")
        bar_l = QHBoxLayout(bar)
        bar_l.setContentsMargins(12, 8, 12, 8)
        bar_l.setSpacing(8)

        bar_l.addWidget(QLabel(_("topo_lbl_mode", "Mode:")))
        self.mode_combo = QComboBox()
        self.mode_combo.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.mode_combo.setMinimumWidth(118)
        for m in VIEW_MODES:
            self.mode_combo.addItem(m, m)
        self.mode_combo.currentIndexChanged.connect(self.refresh)
        bar_l.addWidget(self.mode_combo)

        bar_l.addWidget(QLabel(_("topo_lbl_site", "Site:")))
        self.site_combo = QComboBox()
        self.site_combo.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.site_combo.setMinimumWidth(148)
        self.site_combo.currentIndexChanged.connect(self._on_site_combo_changed)
        bar_l.addWidget(self.site_combo)

        bar_l.addWidget(QLabel(_("topo_lbl_category", "Type:")))
        self.cat_combo = QComboBox()
        self.cat_combo.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.cat_combo.setMinimumWidth(100)
        self.cat_combo.addItem(_("common_all", "All"), None)
        for cat in DEVICE_CATEGORIES:
            self.cat_combo.addItem(cat, cat)
        self.cat_combo.currentIndexChanged.connect(self.refresh)
        bar_l.addWidget(self.cat_combo)

        bar_l.addWidget(QLabel("VLAN:"))
        self.vlan_combo = QComboBox()
        self.vlan_combo.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.vlan_combo.setMinimumWidth(148)
        self.vlan_combo.currentIndexChanged.connect(self.refresh)
        bar_l.addWidget(self.vlan_combo)

        self.search_input = QLineEdit()
        self.search_input.setMinimumWidth(100)
        self.search_input.setPlaceholderText(_("topo_search_ph", "Filter hostname, IP, vendor..."))
        self.search_input.textChanged.connect(lambda _txt: self._search_timer.start())
        bar_l.addWidget(self.search_input, 1)

        zoom_in = QPushButton("+")
        zoom_in.setObjectName("IconButton")
        zoom_in.setFixedSize(32, 32)
        zoom_in.setToolTip("Zoom In")
        zoom_in.setCursor(Qt.PointingHandCursor)
        zoom_in.clicked.connect(lambda: self.canvas.apply_zoom_factor(1.2))
        zoom_out = QPushButton("-")
        zoom_out.setObjectName("IconButton")
        zoom_out.setFixedSize(32, 32)
        zoom_out.setToolTip("Zoom Out")
        zoom_out.setCursor(Qt.PointingHandCursor)
        zoom_out.clicked.connect(lambda: self.canvas.apply_zoom_factor(1.0 / 1.2))
        fit_btn = QPushButton(_("topo_btn_fit", "Fit"))
        fit_btn.setObjectName("SecondaryButton")
        fit_btn.setToolTip(_("topo_btn_fit", "Fit Graph to View"))
        fit_btn.setCursor(Qt.PointingHandCursor)
        fit_btn.clicked.connect(self.canvas_fit)
        bar_l.addWidget(zoom_out)
        bar_l.addWidget(zoom_in)
        bar_l.addWidget(fit_btn)
        root.addWidget(bar)

        # Live Discovery Context Banner (shown automatically during live current-network discovery)
        self.live_banner = QFrame()
        self.live_banner.setObjectName("LiveBanner")
        self.live_banner.setStyleSheet(
            "#LiveBanner { background-color: rgba(16, 185, 129, 0.08); "
            "border: 1px solid rgba(16, 185, 129, 0.35); border-radius: 10px; }"
        )
        lb_l = QHBoxLayout(self.live_banner)
        lb_l.setContentsMargins(14, 8, 12, 8)
        lb_l.setSpacing(10)

        live_dot = QLabel("●")
        live_dot.setStyleSheet("color: #10B981; font-size: 14px;")
        lb_l.addWidget(live_dot)

        self.live_banner_lbl = QLabel("")
        self.live_banner_lbl.setWordWrap(True)
        self.live_banner_lbl.setStyleSheet("color: #E2E8F0; font-size: 12px; font-weight: 600;")
        lb_l.addWidget(self.live_banner_lbl, 1)

        self.btn_add_all_site = QPushButton(_("topo_btn_add_all_site", "+ Add All to Site..."))
        self.btn_add_all_site.setObjectName("PrimaryButton")
        self.btn_add_all_site.setCursor(Qt.PointingHandCursor)
        self.btn_add_all_site.clicked.connect(self._open_assign_all_live_dialog)
        lb_l.addWidget(self.btn_add_all_site)

        self.btn_exit_live = QPushButton(_("topo_btn_exit_live", "Saved Sites"))
        self.btn_exit_live.setObjectName("SecondaryButton")
        self.btn_exit_live.setCursor(Qt.PointingHandCursor)
        self.btn_exit_live.clicked.connect(self.set_saved_scope)
        lb_l.addWidget(self.btn_exit_live)

        self.live_banner.setVisible(False)
        root.addWidget(self.live_banner)

        # Main Splitter: Canvas + Right Inspection Panel
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.canvas = TopologyCanvas()
        self.canvas.node_selected.connect(self._on_node_selected)
        self.canvas.node_context_action.connect(self._on_node_context_action)
        self.canvas.canvas_cleared.connect(self._clear_inspector)
        self.canvas.layout_modified.connect(self._on_layout_modified)
        splitter.addWidget(self.canvas)

        # Details Panel
        self.detail_panel = QFrame()
        self.detail_panel.setObjectName("PanelCard")
        self.detail_panel.setMinimumWidth(365)
        self.detail_panel.setMaximumWidth(420)
        dp_l = QVBoxLayout(self.detail_panel)
        dp_l.setContentsMargins(12, 10, 12, 10)
        dp_l.setSpacing(6)

        self.dp_title = QLabel(_("topo_detail_title", "Device Inspector"))
        self.dp_title.setObjectName("SectionHeader")
        self.dp_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #F8FAFC;")
        dp_l.addWidget(self.dp_title)

        info_scroll = QScrollArea()
        info_scroll.setWidgetResizable(True)
        info_scroll.setFrameShape(QFrame.NoFrame)
        info_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        info_body = QWidget()
        form = QFormLayout(info_body)
        form.setContentsMargins(0, 0, 4, 0)
        form.setSpacing(4)
        self.lbl_host = QLabel("-")
        self.lbl_ip = QLabel("-")
        self.lbl_mac = QLabel("-")
        self.lbl_cat = QLabel("-")
        self.lbl_vendor = QLabel("-")
        self.lbl_site = QLabel("-")
        self.lbl_status = QLabel("-")
        self.lbl_source = QLabel("-")
        self.lbl_upstream = QLabel("-")
        self.lbl_downstream = QLabel("-")
        self.lbl_conn = QLabel("0")
        for lbl in (
            self.lbl_host,
            self.lbl_ip,
            self.lbl_mac,
            self.lbl_cat,
            self.lbl_vendor,
            self.lbl_site,
            self.lbl_status,
            self.lbl_source,
            self.lbl_upstream,
            self.lbl_downstream,
            self.lbl_conn,
        ):
            lbl.setWordWrap(True)
            lbl.setStyleSheet("color: #E2E8F0; font-size: 12px;")
            lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)

        form.addRow(_("inv_col_host", "Hostname:"), self.lbl_host)
        form.addRow(_("topo_col_ip", "IP Address:"), self.lbl_ip)
        form.addRow(_("topo_col_mac", "MAC:"), self.lbl_mac)
        form.addRow(_("inv_col_cat", "Category:"), self.lbl_cat)
        form.addRow(_("inv_col_vendor", "Vendor:"), self.lbl_vendor)
        form.addRow(_("topo_col_site", "Site:"), self.lbl_site)
        form.addRow(_("topo_col_status", "Status:"), self.lbl_status)
        form.addRow(_("topo_lbl_source", "Discovery:"), self.lbl_source)
        form.addRow(_("topo_lbl_upstream", "Fed By (Uplink):"), self.lbl_upstream)
        form.addRow(_("topo_lbl_downstream", "Feeds (Downstream):"), self.lbl_downstream)
        form.addRow(_("topo_lbl_connected", "Connected Links:"), self.lbl_conn)
        info_scroll.setMinimumHeight(105)
        info_scroll.setWidget(info_body)
        dp_l.addWidget(info_scroll, 5)

        dp_l.addWidget(QLabel(_("topo_lbl_links", "Discovered Links:")))
        self.links_table = QTableWidget(0, 4)
        self.links_table.setHorizontalHeaderLabels([
            _("topo_col_neighbor", "Neighbor"),
            _("topo_col_local_port", "Local"),
            _("topo_col_remote_port", "Remote"),
            _("topo_col_method", "Method"),
        ])
        links_hdr = self.links_table.horizontalHeader()
        links_hdr.setSectionResizeMode(QHeaderView.Interactive)
        links_hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        self.links_table.setColumnWidth(1, 62)
        self.links_table.setColumnWidth(2, 66)
        self.links_table.setColumnWidth(3, 66)
        self.links_table.setMinimumHeight(80)
        self.links_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.links_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.links_table.verticalHeader().setVisible(False)
        dp_l.addWidget(self.links_table, 3)

        btn_col = QVBoxLayout()
        btn_col.setSpacing(6)
        self.btn_add_to_site = QPushButton(_("topo_btn_add_site", "+ Add to Site..."))
        self.btn_add_to_site.setObjectName("PrimaryButton")
        self.btn_add_to_site.setCursor(Qt.PointingHandCursor)
        self.btn_add_to_site.setEnabled(False)
        self.btn_add_to_site.clicked.connect(lambda: self._open_assign_to_site_dialog([self._selected_node]) if self._selected_node else None)

        self.btn_access = QPushButton(_("topo_btn_access", "Open in Access Center"))
        self.btn_access.setObjectName("SecondaryButton")
        self.btn_access.setCursor(Qt.PointingHandCursor)
        self.btn_access.setEnabled(False)
        self.btn_access.clicked.connect(self._emit_open_access)

        self.btn_web = QPushButton(_("topo_btn_web", "Web UI"))
        self.btn_web.setObjectName("SecondaryButton")
        self.btn_web.setCursor(Qt.PointingHandCursor)
        self.btn_web.setEnabled(False)
        self.btn_web.clicked.connect(self._emit_open_web)

        btn_col.addWidget(self.btn_add_to_site)
        btn_col.addWidget(self.btn_access)
        btn_col.addWidget(self.btn_web)
        dp_l.addLayout(btn_col)

        splitter.addWidget(self.detail_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([635, 365])
        root.addWidget(splitter, 1)

        # Bottom Legend + Summary Bar
        legend = QHBoxLayout()
        for key, label in [
            ("UP", _("topo_leg_up", "Healthy")),
            ("DEGRADED", _("topo_leg_deg", "Degraded")),
            ("DOWN", _("topo_leg_down", "Unavailable")),
            ("UNKNOWN", _("topo_leg_unk", "Unknown")),
            ("SELECTED", _("topo_leg_sel", "Selected")),
        ]:
            dot = QLabel("●")
            dot.setStyleSheet(f"color: {STATUS_COLOR_MAP[key]}; font-size: 13px;")
            txt = QLabel(label)
            txt.setStyleSheet("color: #CBD5E1; font-size: 11px; margin-right: 12px;")
            legend.addWidget(dot)
            legend.addWidget(txt)

        legend.addStretch()
        self.status_summary = QLabel(_("topo_ready", "Ready"))
        self.status_summary.setStyleSheet("color: #94A3B8; font-size: 12px;")
        legend.addWidget(self.status_summary)
        root.addLayout(legend)

    def _current_layout_name(self) -> str:
        mode = self.mode_combo.currentData() or "PHYSICAL"
        if self._view_scope == "LIVE":
            return f"topo_LIVE_{mode}"
        site_id = self.site_combo.currentData()
        return f"topo_{mode}_{site_id if site_id is not None else 'ALL'}"

    def _on_site_combo_changed(self) -> None:
        sel = self.site_combo.currentData()
        if sel == self._LIVE_SCOPE_DATA and self._live_payload is not None:
            self._view_scope = "LIVE"
        else:
            self._view_scope = "SAVED"
        self.refresh()

    def set_saved_scope(self) -> None:
        self._view_scope = "SAVED"
        if self.site_combo.currentData() == self._LIVE_SCOPE_DATA:
            self.site_combo.blockSignals(True)
            idx_all = self.site_combo.findData(None)
            self.site_combo.setCurrentIndex(idx_all if idx_all >= 0 else 0)
            self.site_combo.blockSignals(False)
        self.refresh()

    def _reload_filter_options(self) -> None:
        cur_site = self._LIVE_SCOPE_DATA if self._view_scope == "LIVE" else self.site_combo.currentData()
        if cur_site == self._LIVE_SCOPE_DATA and self._live_payload is None:
            cur_site = None
            self._view_scope = "SAVED"
        cur_vlan = self.vlan_combo.currentData()

        self.site_combo.blockSignals(True)
        self.site_combo.clear()
        if self._live_payload is not None:
            self.site_combo.addItem(_("topo_live_scope_item", "Live Current Network"), self._LIVE_SCOPE_DATA)
        self.site_combo.addItem(_("common_all_sites", "All Sites"), None)
        for s in self.site_manager.list_sites():
            self.site_combo.addItem(s["name"], s["id"])
        idx = self.site_combo.findData(cur_site)
        if idx >= 0:
            self.site_combo.setCurrentIndex(idx)
        else:
            idx_all = self.site_combo.findData(None)
            if idx_all >= 0:
                self.site_combo.setCurrentIndex(idx_all)
        self.site_combo.blockSignals(False)

        self.vlan_combo.blockSignals(True)
        self.vlan_combo.clear()
        self.vlan_combo.addItem(_("common_all_vlans", "All VLANs"), None)
        with self.db.Session() as session:
            rows = (
                session.query(InfrastructureVlan.vlan_number, InfrastructureVlan.vlan_name)
                .distinct()
                .order_by(InfrastructureVlan.vlan_number.asc())
                .all()
            )
        seen_vids: Set[int] = set()
        for vid, vname in rows:
            if vid in seen_vids:
                continue
            seen_vids.add(vid)
            self.vlan_combo.addItem(f"VLAN {vid} ({vname})" if vname else f"VLAN {vid}", vid)
        vidx = self.vlan_combo.findData(cur_vlan)
        if vidx >= 0:
            self.vlan_combo.setCurrentIndex(vidx)
        self.vlan_combo.blockSignals(False)

    def _build_filtered_live_graph(self, mode: str, category: Optional[str], search: str) -> Dict[str, Any]:
        payload = self._live_payload or {"nodes": [], "edges": []}
        raw_nodes = [dict(n) for n in payload.get("nodes", [])]
        raw_edges = [dict(e) for e in payload.get("edges", [])]

        term = search.lower()
        kept_ids: Set[int] = set()
        for n in raw_nodes:
            if category and n.get("category") != category:
                continue
            if term:
                hay = " ".join([
                    str(n.get("hostname") or ""),
                    str(n.get("management_ip") or ""),
                    str(n.get("mac_address") or ""),
                    str(n.get("vendor") or ""),
                    str(n.get("category") or ""),
                    str(n.get("site_name") or ""),
                ]).lower()
                if term not in hay:
                    continue
            kept_ids.add(int(n["id"]))

        if term:
            for e in raw_edges:
                s = int(e["source_device_id"])
                d = int(e["dest_device_id"])
                if s in kept_ids or d in kept_ids:
                    kept_ids.add(s)
                    kept_ids.add(d)

        filtered_nodes = [n for n in raw_nodes if int(n["id"]) in kept_ids]
        filtered_edges = [
            e for e in raw_edges
            if int(e["source_device_id"]) in kept_ids and int(e["dest_device_id"]) in kept_ids
        ]
        if mode == "PHYSICAL":
            filtered_edges = [e for e in filtered_edges if str(e.get("link_type") or "").upper() != "LOGICAL"]
        elif mode == "LOGICAL":
            filtered_edges = [
                e for e in filtered_edges
                if str(e.get("link_type") or "").upper() in ("LOGICAL", "UPLINK", "GATEWAY_UPLINK", "AP_UPLINK")
            ]

        gw_ips = {str(n.get("management_ip") or "") for n in filtered_nodes if n.get("is_gateway") and n.get("management_ip")}
        orient_topology_hierarchy(filtered_nodes, filtered_edges, gateway_ips=gw_ips)
        return {"view_mode": mode, "nodes": filtered_nodes, "edges": filtered_edges}

    def _update_live_banner(self) -> None:
        if self._view_scope == "LIVE" and self._live_payload is not None:
            gw = self._live_payload.get("gateway_ip") or "-"
            cidr = self._live_payload.get("subnet_cidr") or "-"
            nodes = self._live_payload.get("nodes") or []
            unassigned = sum(1 for n in nodes if not n.get("site_id"))
            tpl = _(
                "topo_live_banner",
                "LIVE NETWORK - Gateway: {gw} | Subnet: {cidr} | {total} active device(s) ({unassigned} unassigned)",
            )
            self.live_banner_lbl.setText(tpl.format(gw=gw, cidr=cidr, total=len(nodes), unassigned=unassigned))
            self.live_banner.setVisible(True)
        else:
            self.live_banner.setVisible(False)

    def refresh(self) -> None:
        self._reload_filter_options()
        mode = self.mode_combo.currentData() or "PHYSICAL"
        site_sel = self.site_combo.currentData()
        category = self.cat_combo.currentData()
        vlan_num = self.vlan_combo.currentData()
        search = self.search_input.text().strip()

        if self._view_scope == "LIVE" and self._live_payload is not None and site_sel == self._LIVE_SCOPE_DATA:
            graph = self._build_filtered_live_graph(mode, category, search)
            saved_pos: Dict[int, Tuple[float, float]] = {}
            saved_zoom = 1.0
        else:
            site_id = None if site_sel == self._LIVE_SCOPE_DATA else site_sel
            graph = self.graph_service.build_graph(
                view_mode=mode,
                site_id=site_id,
                category_filter=category,
                search=search,
                vlan_number=vlan_num,
            )
            saved_pos, saved_zoom = self.graph_service.load_layout(self._current_layout_name())

        self._update_live_banner()
        self._current_graph = graph
        nodes = graph["nodes"]
        edges = graph["edges"]

        auto_pos = self.graph_service.compute_auto_layout(nodes, view_mode=mode, edges=edges)
        positions = {int(n["id"]): saved_pos.get(int(n["id"]), auto_pos.get(int(n["id"]), (0.0, 0.0))) for n in nodes}

        self.canvas.populate_graph(nodes, edges, positions)
        if saved_pos:
            self.canvas.set_zoom_level(saved_zoom)
        self._has_unsaved_layout = False
        prefix = "LIVE " if (self._view_scope == "LIVE" and self._live_payload is not None) else ""
        self.status_summary.setText(f"{prefix}{mode}: {len(nodes)} devices | {len(edges)} links")

        if self._selected_node is not None:
            cur_id = int(self._selected_node["id"])
            updated = next((n for n in nodes if int(n["id"]) == cur_id), None)
            if updated is not None:
                self._on_node_selected(updated)
            else:
                self._clear_inspector()

    def _clear_inspector(self) -> None:
        self._selected_node = None
        for lbl in (
            self.lbl_host,
            self.lbl_ip,
            self.lbl_mac,
            self.lbl_cat,
            self.lbl_vendor,
            self.lbl_site,
            self.lbl_status,
            self.lbl_source,
            self.lbl_upstream,
            self.lbl_downstream,
        ):
            lbl.setText("-")
        self.lbl_conn.setText("0")
        self.links_table.setRowCount(0)
        self.btn_add_to_site.setText(_("topo_btn_add_site", "+ Add to Site..."))
        self.btn_add_to_site.setEnabled(False)
        self.btn_access.setEnabled(False)
        self.btn_web.setEnabled(False)

    def canvas_fit(self) -> None:
        self.canvas.fit_graph()

    def recompute_auto_layout(self) -> None:
        mode = self.mode_combo.currentData() or "PHYSICAL"
        nodes = self._current_graph.get("nodes", [])
        edges = self._current_graph.get("edges", [])
        positions = self.graph_service.compute_auto_layout(nodes, view_mode=mode, edges=edges)
        self.canvas.apply_positions(positions)
        self.canvas.fit_graph()
        self._has_unsaved_layout = True

    def save_current_layout(self) -> None:
        mode = self.mode_combo.currentData() or "PHYSICAL"
        site_sel = self.site_combo.currentData()
        site_id = None if site_sel == self._LIVE_SCOPE_DATA else site_sel
        positions = self.canvas.current_positions()
        self.graph_service.save_layout(
            layout_name=self._current_layout_name(),
            positions=positions,
            view_mode=mode,
            site_id=site_id,
            zoom_level=self.canvas._zoom_factor,
        )
        self._has_unsaved_layout = False
        self.status_summary.setText(f"Layout saved ({len(positions)} positions)")

    def _on_layout_modified(self) -> None:
        self._has_unsaved_layout = True

    def _on_node_selected(self, node_data: Dict[str, Any]) -> None:
        self._selected_node = node_data
        did = int(node_data["id"])
        self.lbl_host.setText(str(node_data.get("hostname") or "-"))
        self.lbl_ip.setText(str(node_data.get("management_ip") or "-"))
        self.lbl_mac.setText(str(node_data.get("mac_address") or "-"))
        self.lbl_cat.setText(str(node_data.get("category") or "-"))
        self.lbl_vendor.setText(f"{node_data.get('vendor') or 'Unknown'} {node_data.get('model') or ''}".strip())
        self.lbl_site.setText(str(node_data.get("site_name") or "Unassigned"))
        lat = node_data.get("latency_ms")
        st_txt = str(node_data.get("status") or "UNKNOWN")
        if isinstance(lat, (int, float)):
            st_txt = f"{st_txt} ({lat:.1f} ms)"
        self.lbl_status.setText(st_txt)
        self.lbl_source.setText(str(node_data.get("discovery_source") or "MANUAL"))

        # Directional hierarchy readout ("Passerelle & qui donne a qui")
        up_host = str(node_data.get("upstream_hostname") or "").strip()
        up_port = str(node_data.get("upstream_port") or "").strip()
        if node_data.get("is_gateway") and node_data.get("upstream_device_id") is None:
            self.lbl_upstream.setText(_("topo_val_wan_gateway", "Internet / WAN (Default Gateway)"))
        elif up_host:
            self.lbl_upstream.setText(f"{up_host} ({up_port})" if up_port else up_host)
        else:
            self.lbl_upstream.setText(_("topo_val_unlinked", "Independent / Unlinked"))

        dn_names = list(node_data.get("downstream_names") or [])
        if dn_names:
            preview = ", ".join(dn_names[:4])
            if len(dn_names) > 4:
                preview += f" (+{len(dn_names) - 4})"
            self.lbl_downstream.setText(f"{len(dn_names)} : {preview}")
        else:
            self.lbl_downstream.setText(_("topo_val_none", "None (endpoint)"))

        self.lbl_conn.setText(str(node_data.get("connected_count") or 0))

        nodes_by_id = {int(n["id"]): n for n in self._current_graph.get("nodes", [])}
        incident = [
            e for e in self._current_graph.get("edges", [])
            if int(e["source_device_id"]) == did or int(e["dest_device_id"]) == did
        ]
        self.links_table.setRowCount(0)
        for e in incident:
            is_src = int(e["source_device_id"]) == did
            peer_id = int(e["dest_device_id"] if is_src else e["source_device_id"])
            peer = nodes_by_id.get(peer_id, {})
            lport = e.get("source_interface") if is_src else e.get("dest_interface")
            rport = e.get("dest_interface") if is_src else e.get("source_interface")
            arrow = "↓" if is_src else "↑"
            row = self.links_table.rowCount()
            self.links_table.insertRow(row)
            self.links_table.setItem(row, 0, QTableWidgetItem(f"{arrow} {peer.get('hostname') or peer_id}"))
            self.links_table.setItem(row, 1, QTableWidgetItem(str(lport or "-")))
            self.links_table.setItem(row, 2, QTableWidgetItem(str(rport or "-")))
            self.links_table.setItem(row, 3, QTableWidgetItem(str(e.get("discovery_method") or "-")))

        if node_data.get("site_id") is not None:
            self.btn_add_to_site.setText(_("topo_btn_change_site", "Change Site..."))
        else:
            self.btn_add_to_site.setText(_("topo_btn_add_site", "+ Add to Site..."))
        self.btn_add_to_site.setEnabled(True)

        has_ip = _is_valid_probe_ip(str(node_data.get("management_ip") or ""))
        self.btn_access.setEnabled(has_ip)
        self.btn_web.setEnabled(has_ip)

    def _on_node_context_action(self, action: str, node_data: Dict[str, Any]) -> None:
        if action == "add_to_site":
            self._open_assign_to_site_dialog([node_data])
        elif action == "toggle_gateway":
            self._toggle_node_gateway(node_data)
        elif action == "open_access":
            self._selected_node = node_data
            self._emit_open_access()
        elif action == "open_web":
            self._selected_node = node_data
            self._emit_open_web()
        elif action == "copy_ip":
            cb = QApplication.clipboard()
            if cb is not None:
                cb.setText(str(node_data.get("management_ip") or ""))
        elif action == "copy_mac":
            cb = QApplication.clipboard()
            if cb is not None:
                cb.setText(str(node_data.get("mac_address") or ""))

    def _toggle_node_gateway(self, node_data: Dict[str, Any]) -> None:
        nid = int(node_data["id"])
        new_state = not bool(node_data.get("is_gateway"))
        if self._view_scope == "LIVE" and self._live_payload is not None:
            for n in self._live_payload.get("nodes", []):
                if int(n["id"]) == nid:
                    n["is_gateway"] = new_state
                    if new_state:
                        n["role"] = "Default Gateway"
                        if n.get("category") == "Other":
                            n["category"] = "Router"
                    else:
                        if n.get("role") == "Default Gateway":
                            n["role"] = ""
                    break
            if new_state and _is_valid_probe_ip(str(node_data.get("management_ip") or "")):
                self._live_payload["gateway_ip"] = node_data["management_ip"]
            elif not new_state and self._live_payload.get("gateway_ip") == node_data.get("management_ip"):
                self._live_payload["gateway_ip"] = ""
            self.refresh()
            self.recompute_auto_layout()
            return

        # Persistent saved DB node toggle
        with self.db.Session() as session:
            row = session.query(InfrastructureDevice).filter_by(id=nid).first()
            if row is not None:
                row.role = "Default Gateway" if new_state else ""
                if new_state and (not row.category or row.category == "Other"):
                    row.category = "Router"
                if row.site_id is not None:
                    site_row = session.query(NetworkSite).filter_by(id=row.site_id).first()
                    if site_row is not None:
                        if new_state and _is_valid_probe_ip(row.management_ip):
                            site_row.default_gateway = row.management_ip
                        elif not new_state and site_row.default_gateway == row.management_ip:
                            site_row.default_gateway = ""
                session.commit()
        self.inventory_updated.emit()
        self.refresh()
        self.recompute_auto_layout()

    def _open_assign_all_live_dialog(self) -> None:
        if self._live_payload is None:
            return
        nodes = list(self._live_payload.get("nodes") or [])
        if not nodes:
            return
        self._open_assign_to_site_dialog(nodes)

    def _open_assign_to_site_dialog(self, devices: List[Dict[str, Any]]) -> None:
        if not devices:
            return
        gw = str((self._live_payload or {}).get("gateway_ip") or "")
        cidr = str((self._live_payload or {}).get("subnet_cidr") or "")
        if not gw and len(devices) == 1 and devices[0].get("is_gateway"):
            gw = str(devices[0].get("management_ip") or "")

        dlg = AssignToSiteDialog(
            devices=devices,
            site_manager=self.site_manager,
            default_gateway=gw,
            subnet_cidr=cidr,
            parent=self,
        )
        if dlg.exec() != QDialog.Accepted:
            return
        res = dlg.get_result()
        try:
            outcome = self.assign_devices_to_site(
                devices=res["devices"],
                site_id=res["site_id"],
                new_site_data=res["new_site_data"],
                save_links=res["save_links"],
                hostname_override=res["hostname_override"],
                category_override=res["category_override"],
            )
            self.status_summary.setText(
                _("topo_dlg_saved_ok", "Assigned {count} device(s) to site '{site}' ({links} links saved)").format(
                    count=outcome["assigned_count"],
                    site=outcome["site_name"],
                    links=outcome["links_saved"],
                )
            )
        except Exception as exc:
            QMessageBox.warning(self, _("common_error", "Error"), str(exc))

    def assign_devices_to_site(
        self,
        devices: List[Dict[str, Any]],
        site_id: Optional[int] = None,
        new_site_data: Optional[Dict[str, Any]] = None,
        save_links: bool = True,
        hostname_override: Optional[str] = None,
        category_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Persist discovered topology node(s) and their links into a target Site cleanly."""
        if new_site_data is not None:
            name_clean = str(new_site_data.get("name") or "").strip()
            existing_site = self.site_manager.get_site_by_name(name_clean)
            if existing_site is not None:
                site = existing_site
            else:
                site = self.site_manager.create_site(new_site_data)
        elif site_id is not None:
            site = self.site_manager.get_site(int(site_id))
            if site is None:
                raise ValueError(f"Site ID {site_id} not found.")
        else:
            raise ValueError("Target site is required.")

        target_site_id = int(site["id"])
        target_site_name = str(site["name"])
        inv = InventoryManager(self.db, site_manager=self.site_manager)

        id_remap: Dict[int, int] = {}
        assigned_count = 0
        single = len(devices) == 1
        saved_positions = self.canvas.current_positions()

        for d in devices:
            old_id = int(d["id"])
            db_id = d.get("db_device_id")
            if db_id is None and d.get("already_in_inventory") and old_id > 0:
                db_id = old_id

            host_val = (hostname_override if (single and hostname_override) else str(d.get("hostname") or "")).strip() or str(d.get("management_ip") or "Device")
            cat_val = category_override if (single and category_override) else str(d.get("category") or "Other")
            role_val = "Default Gateway" if d.get("is_gateway") else str(d.get("role") or "")
            mac_val = str(d.get("mac_address") or "").strip()
            ip_val = str(d.get("management_ip") or "").strip() or f"UNKNOWN-IP-{old_id}"

            saved_rec: Optional[Dict[str, Any]] = None
            if db_id is not None:
                saved_rec = inv.update_device(
                    int(db_id),
                    {
                        "site_id": target_site_id,
                        "hostname": host_val,
                        "category": cat_val,
                        "role": role_val,
                        "status": str(d.get("status") or "UNKNOWN").upper(),
                    },
                )

            if saved_rec is None:
                if mac_val:
                    existing_mac = inv.check_duplicate_mac(mac_val)
                    if existing_mac is not None:
                        saved_rec = inv.update_device(
                            int(existing_mac["id"]),
                            {
                                "site_id": target_site_id,
                                "hostname": host_val,
                                "category": cat_val,
                                "role": role_val,
                                "status": str(d.get("status") or "UNKNOWN").upper(),
                            },
                        )

            if saved_rec is None:
                existing_ip = inv.check_duplicate_ip(ip_val)
                if existing_ip is not None and (not mac_val or not existing_ip.get("mac_address") or existing_ip.get("mac_address") == mac_val):
                    saved_rec = inv.update_device(
                        int(existing_ip["id"]),
                        {
                            "site_id": target_site_id,
                            "hostname": host_val,
                            "mac_address": mac_val or existing_ip.get("mac_address", ""),
                            "category": cat_val,
                            "role": role_val,
                            "status": str(d.get("status") or "UNKNOWN").upper(),
                        },
                    )

            if saved_rec is None:
                saved_rec = inv.add_device(
                    {
                        "site_id": target_site_id,
                        "hostname": host_val,
                        "management_ip": ip_val,
                        "mac_address": mac_val,
                        "vendor": str(d.get("vendor") or "Unknown"),
                        "model": str(d.get("model") or ""),
                        "category": cat_val,
                        "role": role_val,
                        "discovery_source": str(d.get("discovery_source") or "TOPOLOGY_LIVE"),
                        "status": str(d.get("status") or "UNKNOWN").upper(),
                    },
                    allow_duplicate_ip=True,
                )

            new_db_id = int(saved_rec["id"])
            id_remap[old_id] = new_db_id
            assigned_count += 1

            if d.get("is_gateway") and _is_valid_probe_ip(ip_val) and not site.get("default_gateway"):
                site = self.site_manager.update_site(target_site_id, {"default_gateway": ip_val}) or site

        # Persist live links whose both endpoints now exist in DB
        links_saved = 0
        if save_links and self._live_payload is not None:
            all_old_to_db: Dict[int, int] = dict(id_remap)
            for n in self._live_payload.get("nodes", []):
                nid = int(n["id"])
                if nid not in all_old_to_db and n.get("db_device_id"):
                    all_old_to_db[nid] = int(n["db_device_id"])

            with self.db.Session() as session:
                for edge in self._live_payload.get("edges", []):
                    s_old = int(edge["source_device_id"])
                    d_old = int(edge["dest_device_id"])
                    s_db = all_old_to_db.get(s_old)
                    d_db = all_old_to_db.get(d_old)
                    if not s_db or not d_db or s_db == d_db:
                        continue
                    if s_old not in id_remap and d_old not in id_remap:
                        continue
                    TopologyDiscoveryEngine._upsert_link(
                        session,
                        src_id=s_db,
                        dst_id=d_db,
                        src_if=str(edge.get("source_interface") or ""),
                        dst_if=str(edge.get("dest_interface") or ""),
                        link_type=str(edge.get("link_type") or "PHYSICAL"),
                        discovery_method=str(edge.get("discovery_method") or "GATEWAY_ARP"),
                        confidence=str(edge.get("confidence") or "MEDIUM"),
                        evidence=list(edge.get("evidence") or []),
                        vlan_ids=list(edge.get("vlan_ids") or []),
                    )
                    links_saved += 1
                session.commit()

        # Patch live payload in-place so assigned cards reflect new DB ID & Site immediately
        if self._live_payload is not None:
            for n in self._live_payload.get("nodes", []):
                old_nid = int(n["id"])
                if old_nid in id_remap:
                    new_nid = id_remap[old_nid]
                    n["id"] = new_nid
                    n["db_device_id"] = new_nid
                    n["site_id"] = target_site_id
                    n["site_name"] = target_site_name
                    n["already_in_inventory"] = True
                    if single and hostname_override:
                        n["hostname"] = hostname_override
                    if single and category_override:
                        n["category"] = category_override
            for e in self._live_payload.get("edges", []):
                if int(e["source_device_id"]) in id_remap:
                    e["source_device_id"] = id_remap[int(e["source_device_id"])]
                if int(e["dest_device_id"]) in id_remap:
                    e["dest_device_id"] = id_remap[int(e["dest_device_id"])]

            # Update selected node pointer if it was remapped
            if self._selected_node is not None and int(self._selected_node["id"]) in id_remap:
                target_nid = id_remap[int(self._selected_node["id"])]
                self._selected_node = next(
                    (n for n in self._live_payload["nodes"] if int(n["id"]) == target_nid),
                    self._selected_node,
                )

        self.inventory_updated.emit()
        self.refresh()

        # Preserve screen positions across ephemeral->DB ID remap in Live mode
        if self._view_scope == "LIVE" and saved_positions:
            remapped_pos = {
                id_remap.get(old_k, old_k): pos_val
                for old_k, pos_val in saved_positions.items()
            }
            self.canvas.apply_positions(remapped_pos)

        return {
            "site_id": target_site_id,
            "site_name": target_site_name,
            "assigned_count": assigned_count,
            "links_saved": links_saved,
            "id_remap": id_remap,
        }

    def _emit_open_access(self) -> None:
        if self._selected_node:
            self.open_in_access_center.emit(self._selected_node)

    def _emit_open_web(self) -> None:
        if self._selected_node and self._selected_node.get("management_ip"):
            self.open_in_browser.emit(f"https://{self._selected_node['management_ip']}")

    def start_discovery(self) -> None:
        if (self._live_worker and self._live_worker.isRunning()) or (self._discovery_worker and self._discovery_worker.isRunning()):
            return
        self.discover_btn.setEnabled(False)
        self.check_status_btn.setEnabled(False)
        self.status_summary.setText(_("topo_live_scanning", "Scanning active local network right now..."))
        db_path = getattr(self.db, "db_path", None)
        self._live_worker = TopologyLiveDiscoveryWorker(db_path=db_path)
        self._live_worker.finished_live.connect(self._on_live_discovery_finished)
        self._live_worker.failed.connect(self._on_discovery_failed)
        self._live_worker.start()

    def _on_live_discovery_finished(self, payload: Dict[str, Any]) -> None:
        self.discover_btn.setEnabled(True)
        self.check_status_btn.setEnabled(True)
        self._live_payload = payload
        self._view_scope = "LIVE"
        self.refresh()
        self.recompute_auto_layout()
        self.canvas_fit()
        summ = payload.get("summary") or {}
        self.status_summary.setText(
            f"Live: {summ.get('devices_discovered', 0)} active "
            f"({summ.get('online_devices', 0)} online, {summ.get('new_unassigned', 0)} new) "
            f"| {summ.get('links_discovered', 0)} links"
        )

    def _on_discovery_finished(self, summary: Dict[str, Any]) -> None:
        self.discover_btn.setEnabled(True)
        self.check_status_btn.setEnabled(True)
        self.refresh()
        self.canvas_fit()
        self.status_summary.setText(
            f"Discovery done: {summary.get('devices_discovered', 0)} discovered "
            f"({summary.get('online_devices', 0)} online, {summary.get('degraded_devices', 0)} degraded, "
            f"{summary.get('down_devices', 0)} down) | {summary.get('links_discovered', 0)} links"
        )

    def _on_discovery_failed(self, err: str) -> None:
        self.discover_btn.setEnabled(True)
        self.check_status_btn.setEnabled(True)
        self.status_summary.setText(f"Discovery error: {err}")

    def start_status_check(self) -> None:
        if self._status_worker and self._status_worker.isRunning():
            return
        self.discover_btn.setEnabled(False)
        self.check_status_btn.setEnabled(False)
        self.status_summary.setText(_("topo_checking_status", "Probing live device statuses..."))

        if self._view_scope == "LIVE" and self._live_payload is not None:
            ips = [
                str(n.get("management_ip") or "")
                for n in self._live_payload.get("nodes", [])
                if _is_valid_probe_ip(str(n.get("management_ip") or ""))
            ]
            self._status_worker = TopologyStatusWorker(live_ips=ips)
            self._status_worker.finished_live_probes.connect(self._on_live_status_finished)
            self._status_worker.failed.connect(self._on_status_failed)
            self._status_worker.start()
            return

        site_sel = self.site_combo.currentData()
        site_id = None if site_sel == self._LIVE_SCOPE_DATA else site_sel
        db_path = getattr(self.db, "db_path", None)
        self._status_worker = TopologyStatusWorker(db_path=db_path, site_id=site_id)
        self._status_worker.finished_status.connect(self._on_status_finished)
        self._status_worker.failed.connect(self._on_status_failed)
        self._status_worker.start()

    def _on_live_status_finished(self, probed: Dict[str, Tuple[str, Optional[float]]]) -> None:
        self.discover_btn.setEnabled(True)
        self.check_status_btn.setEnabled(True)
        counts = {"probed": len(probed), "online": 0, "degraded": 0, "down": 0, "unknown": 0}
        if self._live_payload is not None:
            for n in self._live_payload.get("nodes", []):
                ip = str(n.get("management_ip") or "")
                if ip in probed:
                    st_val, lat_val = probed[ip]
                    n["status"] = st_val
                    n["latency_ms"] = lat_val
                    n["color"] = resolve_status_color(st_val)
                cur = str(n.get("status") or "UNKNOWN").upper()
                if cur in ("ONLINE", "UP", "OK"):
                    counts["online"] += 1
                elif cur in ("DEGRADED", "WARNING", "RECOVERING"):
                    counts["degraded"] += 1
                elif cur in ("DOWN", "OFFLINE", "CRITICAL"):
                    counts["down"] += 1
                else:
                    counts["unknown"] += 1
        self.refresh()
        self.status_summary.setText(
            f"Live check ({counts['probed']} probed): "
            f"{counts['online']} online, {counts['degraded']} degraded, "
            f"{counts['down']} down, {counts['unknown']} unknown"
        )

    def _on_status_finished(self, counts: Dict[str, int]) -> None:
        self.discover_btn.setEnabled(True)
        self.check_status_btn.setEnabled(True)
        self.refresh()
        self.status_summary.setText(
            f"Live check ({counts.get('probed', 0)} probed): "
            f"{counts.get('online', 0)} online, {counts.get('degraded', 0)} degraded, "
            f"{counts.get('down', 0)} down, {counts.get('unknown', 0)} unknown"
        )

    def _on_status_failed(self, err: str) -> None:
        self.discover_btn.setEnabled(True)
        self.check_status_btn.setEnabled(True)
        self.status_summary.setText(f"Live status check error: {err}")

    def export_png(self) -> None:
        path, _flt = QFileDialog.getSaveFileName(self, _("topo_export_png_title", "Export Topology Map"), "topology.png", "PNG Files (*.png)")
        if not path:
            return
        raw_rect = self.canvas.scene_obj.itemsBoundingRect()
        if raw_rect.isNull():
            rect = QRectF(0, 0, 800, 600)
        else:
            rect = raw_rect.adjusted(-40, -40, 40, 40)
        img = QPixmap(int(max(400, rect.width())), int(max(300, rect.height())))
        img.fill(QColor("#0A101D"))
        painter = QPainter(img)
        painter.setRenderHint(QPainter.Antialiasing)
        self.canvas.scene_obj.render(painter, QRectF(img.rect()), rect)
        painter.end()
        img.save(path, "PNG")

    def shutdown(self) -> None:
        if hasattr(self, "_search_timer") and self._search_timer.isActive():
            self._search_timer.stop()
        for worker in (self._live_worker, self._discovery_worker, self._status_worker):
            if worker and worker.isRunning():
                worker.request_stop()
                worker.quit()
                worker.wait(3000)
