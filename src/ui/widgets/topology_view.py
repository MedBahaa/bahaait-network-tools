import asyncio
import math
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import QPointF, QRectF, Qt, QThread, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
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
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.inventory_manager import DEVICE_CATEGORIES
from core.site_manager import SiteManager
from core.topology_discovery import TopologyDiscoveryEngine
from core.topology_graph import (
    STATUS_COLOR_MAP,
    VIEW_MODES,
    TopologyGraphService,
    resolve_status_color,
)
from utils.db import DatabaseManager, InfrastructureVlan
from utils.i18n import _


class TopologyDiscoveryWorker(QThread):
    """Runs multi-source topology discovery and live reachability verification off the UI thread."""

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


class TopologyStatusWorker(QThread):
    """Refreshes live ICMP/TCP reachability statuses for mapped topology nodes off the UI thread."""

    finished_status = Signal(dict)
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
            counts = TopologyDiscoveryEngine(db).refresh_live_statuses(site_id=self.site_id)
            if not self._cancel:
                self.finished_status.emit(counts)
        except Exception as exc:
            if not self._cancel:
                self.failed.emit(str(exc))


class TopologyEdgeItem(QGraphicsPathItem):
    """Visual link connecting two TopologyNodeItem objects with dynamic endpoints."""

    def __init__(self, edge_data: Dict[str, Any], src_item: "TopologyNodeItem", dst_item: "TopologyNodeItem", offset_idx: int = 0) -> None:
        super().__init__()
        self.edge_data = edge_data
        self.src_item = src_item
        self.dst_item = dst_item
        self.offset_idx = offset_idx
        self.setZValue(1)
        self.setAcceptHoverEvents(True)

        src_if = edge_data.get("source_interface") or "?"
        dst_if = edge_data.get("dest_interface") or "?"
        ltype = edge_data.get("link_type") or "PHYSICAL"
        method = edge_data.get("discovery_method") or ""
        conf = edge_data.get("confidence") or ""
        vlans = edge_data.get("vlan_ids") or []
        ev = edge_data.get("evidence") or []
        tip_lines = [
            f"{ltype} ({method} / {conf})",
            f"{src_item.node_data.get('hostname', '')}:{src_if} <-> {dst_item.node_data.get('hostname', '')}:{dst_if}",
        ]
        if vlans:
            tip_lines.append(f"VLANs: {', '.join(str(v) for v in vlans[:12])}")
        if ev:
            tip_lines.append(f"Evidence: {ev[0]}")
        self.setToolTip("\n".join(tip_lines))

        self._hovered = False
        self._apply_pen()
        self.update_positions()

    def _apply_pen(self) -> None:
        status = str(self.edge_data.get("status") or "UP").upper()
        ltype = str(self.edge_data.get("link_type") or "PHYSICAL").upper()
        if status in ("DOWN", "OFFLINE", "CRITICAL"):
            color = QColor(STATUS_COLOR_MAP["DOWN"])
        elif status in ("DEGRADED", "WARNING"):
            color = QColor(STATUS_COLOR_MAP["DEGRADED"])
        elif ltype == "INTER_SITE":
            color = QColor("#06B6D4")
        elif "VLAN" in ltype:
            color = QColor("#818CF8")
        elif ltype == "LOGICAL":
            color = QColor("#6366F1")
        else:
            color = QColor("#475569")

        pen = QPen(color, 2.4 if self._hovered else 1.8)
        if ltype in ("LOGICAL", "INTER_SITE"):
            pen.setStyle(Qt.DashLine)
        elif self.edge_data.get("confidence") == "LOW":
            pen.setStyle(Qt.DotLine)
        self.setPen(pen)

    def hoverEnterEvent(self, event) -> None:
        self._hovered = True
        self._apply_pen()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event) -> None:
        self._hovered = False
        self._apply_pen()
        super().hoverLeaveEvent(event)

    def update_positions(self) -> None:
        p1 = self.src_item.center_pos()
        p2 = self.dst_item.center_pos()
        path = QPainterPath(p1)
        if self.offset_idx == 0:
            path.lineTo(p2)
        else:
            dx = p2.x() - p1.x()
            dy = p2.y() - p1.y()
            dist = math.hypot(dx, dy) or 1.0
            nx, ny = -dy / dist, dx / dist
            shift = (18.0 if self.offset_idx % 2 == 1 else -18.0) * ((self.offset_idx + 1) // 2)
            ctrl = QPointF((p1.x() + p2.x()) / 2.0 + nx * shift, (p1.y() + p2.y()) / 2.0 + ny * shift)
            path.quadTo(ctrl, p2)
        self.setPath(path)


def _category_glyph(category: str) -> str:
    c = (category or "").lower()
    if "firewall" in c:
        return "FW"
    if "router" in c:
        return "RTR"
    if "core" in c:
        return "CORE"
    if "distribution" in c:
        return "DIST"
    if "access switch" in c:
        return "SW"
    if "controller" in c:
        return "WLC"
    if "wireless" in c or "ap" in c:
        return "AP"
    if "server" in c:
        return "SRV"
    if "ups" in c:
        return "UPS"
    if "printer" in c:
        return "PRT"
    return "DEV"


class TopologyNodeItem(QGraphicsObject):
    """Movable, selectable Quantum Midnight device node with dynamic edge tracking."""

    moved = Signal(int, float, float)
    clicked = Signal(dict)

    WIDTH = 148.0
    HEIGHT = 68.0

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
        self.setToolTip(
            f"{node_data.get('hostname', '')}\n"
            f"IP: {node_data.get('management_ip', '-')}\n"
            f"Category: {node_data.get('category', 'Other')}\n"
            f"Vendor: {node_data.get('vendor', 'Unknown')}\n"
            f"Site: {node_data.get('site_name', 'Unassigned')}\n"
            f"Status: {node_data.get('status', 'UNKNOWN')} | Links: {node_data.get('connected_count', 0)}"
        )

    def boundingRect(self) -> QRectF:
        return QRectF(-4.0, -4.0, self.WIDTH + 8.0, self.HEIGHT + 8.0)

    def center_pos(self) -> QPointF:
        return self.pos() + QPointF(self.WIDTH / 2.0, self.HEIGHT / 2.0)

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

    def paint(self, painter: QPainter, option, widget=None) -> None:
        painter.setRenderHint(QPainter.Antialiasing)
        selected = self.isSelected()
        status = str(self.node_data.get("status") or "UNKNOWN").upper()
        accent_hex = resolve_status_color(status, selected=selected)
        status_hex = resolve_status_color(status, selected=False)

        card_rect = QRectF(0.0, 0.0, self.WIDTH, self.HEIGHT)
        bg = QColor("#1E293B") if not self._hovered else QColor("#26354B")
        if selected:
            bg = QColor("#1E3A5F")
        painter.setBrush(QBrush(bg))
        border_pen = QPen(QColor(accent_hex), 2.4 if selected else 1.5)
        painter.setPen(border_pen)
        painter.drawRoundedRect(card_rect, 10.0, 10.0)

        # Left status bar strip
        strip_rect = QRectF(0.0, 6.0, 4.0, self.HEIGHT - 12.0)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(QColor(status_hex)))
        painter.drawRoundedRect(strip_rect, 2.0, 2.0)

        # Role / Category badge
        glyph = _category_glyph(str(self.node_data.get("category") or ""))
        badge_rect = QRectF(10.0, 10.0, 34.0, 22.0)
        painter.setBrush(QBrush(QColor("#0F172A")))
        painter.setPen(QPen(QColor(accent_hex), 1.0))
        painter.drawRoundedRect(badge_rect, 5.0, 5.0)

        badge_font = QFont("Segoe UI", 7, QFont.Bold)
        painter.setFont(badge_font)
        painter.setPen(QColor("#F8FAFC"))
        painter.drawText(badge_rect, Qt.AlignCenter, glyph)

        # Status dot (top-right)
        painter.setBrush(QBrush(QColor(status_hex)))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(self.WIDTH - 12.0, 14.0), 4.5, 4.5)

        # Hostname
        title_font = QFont("Segoe UI", 8, QFont.Bold)
        painter.setFont(title_font)
        painter.setPen(QColor("#F8FAFC"))
        host = str(self.node_data.get("hostname") or "Unknown")
        if len(host) > 15:
            host = host[:14] + "…"
        painter.drawText(QRectF(50.0, 9.0, self.WIDTH - 68.0, 20.0), Qt.AlignVCenter | Qt.AlignLeft, host)

        # IP address & Vendor / Connections footer
        sub_font = QFont("Consolas", 7)
        painter.setFont(sub_font)
        painter.setPen(QColor("#94A3B8"))
        ip_txt = str(self.node_data.get("management_ip") or "No IP")
        painter.drawText(QRectF(10.0, 35.0, self.WIDTH - 20.0, 15.0), Qt.AlignVCenter | Qt.AlignLeft, ip_txt)

        meta_font = QFont("Segoe UI", 7)
        painter.setFont(meta_font)
        painter.setPen(QColor("#64748B"))
        deg = int(self.node_data.get("connected_count") or 0)
        cat_short = str(self.node_data.get("category") or "Other")[:15]
        painter.drawText(QRectF(10.0, 50.0, self.WIDTH - 48.0, 14.0), Qt.AlignVCenter | Qt.AlignLeft, cat_short)
        painter.setPen(QColor("#38BDF8"))
        painter.drawText(QRectF(self.WIDTH - 44.0, 50.0, 36.0, 14.0), Qt.AlignVCenter | Qt.AlignRight, f"{deg}L")


class TopologyCanvas(QGraphicsView):
    """Interactive pan/zoom QGraphicsView hosting the TopologyNodeItem/EdgeItem graph."""

    node_selected = Signal(dict)
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
        self.setStyleSheet("QGraphicsView { background-color: #0B1220; border: 1px solid #1E293B; border-radius: 10px; }")

        self.node_items: Dict[int, TopologyNodeItem] = {}
        self.edge_items: List[TopologyEdgeItem] = []
        self._zoom_factor = 1.0
        self._suppress_move_signal = False

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
                item.moved.connect(self._on_node_moved)
                self.scene_obj.addItem(item)
                self.node_items[int(n["id"])] = item

            pair_counts: Dict[Tuple[int, int], int] = {}
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
                edge_item = TopologyEdgeItem(e, s_item, d_item, offset_idx=idx)
                s_item.attach_edge(edge_item)
                d_item.attach_edge(edge_item)
                self.scene_obj.addItem(edge_item)
                self.edge_items.append(edge_item)

            rect = self.scene_obj.itemsBoundingRect()
            if not rect.isNull():
                self.scene_obj.setSceneRect(rect.adjusted(-250, -250, 250, 250))
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

    def select_device(self, device_id: int) -> None:
        for did, item in self.node_items.items():
            item.setSelected(did == device_id)
            if did == device_id:
                self.centerOn(item)


class TopologyView(QWidget):
    """Network Topology Map view with 4 view modes, background discovery, and inspection drawer."""

    open_in_access_center = Signal(dict)
    open_in_browser = Signal(str)

    def __init__(self, db: Optional[DatabaseManager] = None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.db = db or DatabaseManager()
        self.graph_service = TopologyGraphService(self.db)
        self.site_manager = SiteManager(self.db)
        self._discovery_worker: Optional[TopologyDiscoveryWorker] = None
        self._status_worker: Optional[TopologyStatusWorker] = None
        self._current_graph: Dict[str, Any] = {"view_mode": "PHYSICAL", "nodes": [], "edges": []}
        self._selected_node: Optional[Dict[str, Any]] = None
        self._has_unsaved_layout = False

        self._setup_ui()
        self.refresh()

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(12)

        # Header
        hdr = QHBoxLayout()
        title_col = QVBoxLayout()
        title_lbl = QLabel(_("topo_title", "Network Topology"))
        title_lbl.setStyleSheet("font-size: 20px; font-weight: bold; color: #F8FAFC;")
        sub_lbl = QLabel(_("topo_subtitle", "Automatic multi-source mapping (LLDP, CDP, ARP, SNMP, Bridge MIB)"))
        sub_lbl.setStyleSheet("color: #94A3B8; font-size: 12px;")
        title_col.addWidget(title_lbl)
        title_col.addWidget(sub_lbl)
        hdr.addLayout(title_col)
        hdr.addStretch()

        self.discover_btn = QPushButton(_("topo_btn_discover", "Discover Topology"))
        self.discover_btn.setProperty("class", "PrimaryButton")
        self.discover_btn.clicked.connect(self.start_discovery)
        hdr.addWidget(self.discover_btn)

        self.check_status_btn = QPushButton(_("topo_btn_check_status", "Check Live Status"))
        self.check_status_btn.clicked.connect(self.start_status_check)
        hdr.addWidget(self.check_status_btn)

        self.auto_layout_btn = QPushButton(_("topo_btn_auto_layout", "Auto Layout"))
        self.auto_layout_btn.clicked.connect(self.recompute_auto_layout)
        hdr.addWidget(self.auto_layout_btn)

        self.save_layout_btn = QPushButton(_("topo_btn_save_layout", "Save Layout"))
        self.save_layout_btn.clicked.connect(self.save_current_layout)
        hdr.addWidget(self.save_layout_btn)

        self.export_png_btn = QPushButton(_("topo_btn_export_png", "Export PNG"))
        self.export_png_btn.clicked.connect(self.export_png)
        hdr.addWidget(self.export_png_btn)
        root.addLayout(hdr)

        # Toolbar: View Modes + Filters + Zoom controls
        bar = QFrame()
        bar.setStyleSheet("QFrame { background-color: #1E293B; border: 1px solid #334155; border-radius: 10px; }")
        bar_l = QHBoxLayout(bar)
        bar_l.setContentsMargins(12, 8, 12, 8)
        bar_l.setSpacing(10)

        bar_l.addWidget(QLabel(_("topo_lbl_mode", "Mode:")))
        self.mode_combo = QComboBox()
        for m in VIEW_MODES:
            self.mode_combo.addItem(m, m)
        self.mode_combo.currentIndexChanged.connect(self.refresh)
        bar_l.addWidget(self.mode_combo)

        bar_l.addWidget(QLabel(_("topo_lbl_site", "Site:")))
        self.site_combo = QComboBox()
        self.site_combo.currentIndexChanged.connect(self.refresh)
        bar_l.addWidget(self.site_combo)

        bar_l.addWidget(QLabel(_("topo_lbl_category", "Type:")))
        self.cat_combo = QComboBox()
        self.cat_combo.addItem(_("common_all", "All"), None)
        for cat in DEVICE_CATEGORIES:
            self.cat_combo.addItem(cat, cat)
        self.cat_combo.currentIndexChanged.connect(self.refresh)
        bar_l.addWidget(self.cat_combo)

        bar_l.addWidget(QLabel("VLAN:"))
        self.vlan_combo = QComboBox()
        self.vlan_combo.currentIndexChanged.connect(self.refresh)
        bar_l.addWidget(self.vlan_combo)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(_("topo_search_ph", "Filter hostname, IP, vendor..."))
        self.search_input.textChanged.connect(self.refresh)
        bar_l.addWidget(self.search_input, 1)

        zoom_in = QPushButton("+")
        zoom_in.setFixedWidth(30)
        zoom_in.clicked.connect(lambda: self.canvas.apply_zoom_factor(1.2))
        zoom_out = QPushButton("-")
        zoom_out.setFixedWidth(30)
        zoom_out.clicked.connect(lambda: self.canvas.apply_zoom_factor(1.0 / 1.2))
        fit_btn = QPushButton(_("topo_btn_fit", "Fit"))
        fit_btn.clicked.connect(self.canvas_fit)
        bar_l.addWidget(zoom_out)
        bar_l.addWidget(zoom_in)
        bar_l.addWidget(fit_btn)
        root.addWidget(bar)

        # Main Splitter: Canvas + Right Inspection Panel
        splitter = QSplitter(Qt.Horizontal)
        self.canvas = TopologyCanvas()
        self.canvas.node_selected.connect(self._on_node_selected)
        self.canvas.layout_modified.connect(self._on_layout_modified)
        splitter.addWidget(self.canvas)

        # Details Panel
        self.detail_panel = QFrame()
        self.detail_panel.setMinimumWidth(310)
        self.detail_panel.setMaximumWidth(400)
        self.detail_panel.setStyleSheet("QFrame { background-color: #1E293B; border: 1px solid #334155; border-radius: 10px; }")
        dp_l = QVBoxLayout(self.detail_panel)
        dp_l.setContentsMargins(14, 14, 14, 14)
        dp_l.setSpacing(10)

        self.dp_title = QLabel(_("topo_detail_title", "Device Inspector"))
        self.dp_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #F8FAFC;")
        dp_l.addWidget(self.dp_title)

        form = QFormLayout()
        form.setSpacing(6)
        self.lbl_host = QLabel("-")
        self.lbl_ip = QLabel("-")
        self.lbl_mac = QLabel("-")
        self.lbl_cat = QLabel("-")
        self.lbl_vendor = QLabel("-")
        self.lbl_site = QLabel("-")
        self.lbl_status = QLabel("-")
        self.lbl_source = QLabel("-")
        self.lbl_conn = QLabel("0")
        for lbl in (self.lbl_host, self.lbl_ip, self.lbl_mac, self.lbl_cat, self.lbl_vendor, self.lbl_site, self.lbl_status, self.lbl_source, self.lbl_conn):
            lbl.setStyleSheet("color: #E2E8F0; font-size: 12px;")
            lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)

        form.addRow(_("inv_col_host", "Hostname:"), self.lbl_host)
        form.addRow(_("inv_col_ip", "IP Address:"), self.lbl_ip)
        form.addRow("MAC:", self.lbl_mac)
        form.addRow(_("inv_col_cat", "Category:"), self.lbl_cat)
        form.addRow(_("inv_col_vendor", "Vendor:"), self.lbl_vendor)
        form.addRow(_("inv_col_site", "Site:"), self.lbl_site)
        form.addRow(_("inv_col_status", "Status:"), self.lbl_status)
        form.addRow(_("topo_lbl_source", "Discovery:"), self.lbl_source)
        form.addRow(_("topo_lbl_connected", "Connected Links:"), self.lbl_conn)
        dp_l.addLayout(form)

        dp_l.addWidget(QLabel(_("topo_lbl_links", "Discovered Links:")))
        self.links_table = QTableWidget(0, 4)
        self.links_table.setHorizontalHeaderLabels([
            _("topo_col_neighbor", "Neighbor"),
            _("topo_col_local_port", "Local"),
            _("topo_col_remote_port", "Remote"),
            _("topo_col_method", "Method"),
        ])
        self.links_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.links_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.links_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.links_table.verticalHeader().setVisible(False)
        dp_l.addWidget(self.links_table, 1)

        btn_row = QHBoxLayout()
        self.btn_access = QPushButton(_("topo_btn_access", "Open in Access Center"))
        self.btn_access.setEnabled(False)
        self.btn_access.clicked.connect(self._emit_open_access)
        self.btn_web = QPushButton(_("topo_btn_web", "Web UI"))
        self.btn_web.setEnabled(False)
        self.btn_web.clicked.connect(self._emit_open_web)
        btn_row.addWidget(self.btn_access)
        btn_row.addWidget(self.btn_web)
        dp_l.addLayout(btn_row)

        splitter.addWidget(self.detail_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
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
        site_id = self.site_combo.currentData()
        return f"topo_{mode}_{site_id if site_id is not None else 'ALL'}"

    def _reload_filter_options(self) -> None:
        # Preserve current selections while updating available sites and VLANs
        cur_site = self.site_combo.currentData()
        cur_vlan = self.vlan_combo.currentData()

        self.site_combo.blockSignals(True)
        self.site_combo.clear()
        self.site_combo.addItem(_("common_all_sites", "All Sites"), None)
        for s in self.site_manager.list_sites():
            self.site_combo.addItem(s["name"], s["id"])
        idx = self.site_combo.findData(cur_site)
        if idx >= 0:
            self.site_combo.setCurrentIndex(idx)
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
        seen_vids = set()
        for vid, vname in rows:
            if vid in seen_vids:
                continue
            seen_vids.add(vid)
            self.vlan_combo.addItem(f"VLAN {vid} ({vname})" if vname else f"VLAN {vid}", vid)
        vidx = self.vlan_combo.findData(cur_vlan)
        if vidx >= 0:
            self.vlan_combo.setCurrentIndex(vidx)
        self.vlan_combo.blockSignals(False)

    def refresh(self) -> None:
        self._reload_filter_options()
        mode = self.mode_combo.currentData() or "PHYSICAL"
        site_id = self.site_combo.currentData()
        category = self.cat_combo.currentData()
        vlan_num = self.vlan_combo.currentData()
        search = self.search_input.text().strip()

        graph = self.graph_service.build_graph(
            view_mode=mode,
            site_id=site_id,
            category_filter=category,
            search=search,
            vlan_number=vlan_num,
        )
        self._current_graph = graph
        nodes = graph["nodes"]
        edges = graph["edges"]

        saved_pos, saved_zoom = self.graph_service.load_layout(self._current_layout_name())
        auto_pos = self.graph_service.compute_auto_layout(nodes, view_mode=mode)
        positions = {int(n["id"]): saved_pos.get(int(n["id"]), auto_pos.get(int(n["id"]), (0.0, 0.0))) for n in nodes}

        self.canvas.populate_graph(nodes, edges, positions)
        if saved_pos:
            self.canvas.set_zoom_level(saved_zoom)
        self._has_unsaved_layout = False
        self.status_summary.setText(f"{mode}: {len(nodes)} devices | {len(edges)} links")

    def canvas_fit(self) -> None:
        self.canvas.fit_graph()

    def recompute_auto_layout(self) -> None:
        mode = self.mode_combo.currentData() or "PHYSICAL"
        nodes = self._current_graph.get("nodes", [])
        positions = self.graph_service.compute_auto_layout(nodes, view_mode=mode)
        self.canvas.apply_positions(positions)
        self.canvas.fit_graph()
        self._has_unsaved_layout = True

    def save_current_layout(self) -> None:
        mode = self.mode_combo.currentData() or "PHYSICAL"
        site_id = self.site_combo.currentData()
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
        self.lbl_status.setText(str(node_data.get("status") or "UNKNOWN"))
        self.lbl_source.setText(str(node_data.get("discovery_source") or "MANUAL"))
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
            row = self.links_table.rowCount()
            self.links_table.insertRow(row)
            self.links_table.setItem(row, 0, QTableWidgetItem(str(peer.get("hostname") or peer_id)))
            self.links_table.setItem(row, 1, QTableWidgetItem(str(lport or "-")))
            self.links_table.setItem(row, 2, QTableWidgetItem(str(rport or "-")))
            self.links_table.setItem(row, 3, QTableWidgetItem(str(e.get("discovery_method") or "-")))

        has_ip = bool(node_data.get("management_ip"))
        self.btn_access.setEnabled(has_ip)
        self.btn_web.setEnabled(has_ip)

    def _emit_open_access(self) -> None:
        if self._selected_node:
            self.open_in_access_center.emit(self._selected_node)

    def _emit_open_web(self) -> None:
        if self._selected_node and self._selected_node.get("management_ip"):
            self.open_in_browser.emit(f"https://{self._selected_node['management_ip']}")

    def start_discovery(self) -> None:
        if self._discovery_worker and self._discovery_worker.isRunning():
            return
        self.discover_btn.setEnabled(False)
        self.check_status_btn.setEnabled(False)
        self.status_summary.setText(_("topo_discovering", "Running multi-source topology discovery..."))
        site_id = self.site_combo.currentData()
        db_path = getattr(self.db, "db_path", None)
        self._discovery_worker = TopologyDiscoveryWorker(db_path=db_path, site_id=site_id)
        self._discovery_worker.finished_discovery.connect(self._on_discovery_finished)
        self._discovery_worker.failed.connect(self._on_discovery_failed)
        self._discovery_worker.start()

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
        self.check_status_btn.setEnabled(False)
        self.status_summary.setText(_("topo_checking_status", "Probing live device statuses..."))
        site_id = self.site_combo.currentData()
        db_path = getattr(self.db, "db_path", None)
        self._status_worker = TopologyStatusWorker(db_path=db_path, site_id=site_id)
        self._status_worker.finished_status.connect(self._on_status_finished)
        self._status_worker.failed.connect(self._on_status_failed)
        self._status_worker.start()

    def _on_status_finished(self, counts: Dict[str, int]) -> None:
        self.check_status_btn.setEnabled(True)
        self.refresh()
        self.status_summary.setText(
            f"Live check ({counts.get('probed', 0)} probed): "
            f"{counts.get('online', 0)} online, {counts.get('degraded', 0)} degraded, "
            f"{counts.get('down', 0)} down, {counts.get('unknown', 0)} unknown"
        )

    def _on_status_failed(self, err: str) -> None:
        self.check_status_btn.setEnabled(True)
        self.status_summary.setText(f"Live status check error: {err}")

    def export_png(self) -> None:
        path, _flt = QFileDialog.getSaveFileName(self, _("topo_export_png_title", "Export Topology Map"), "topology.png", "PNG Files (*.png)")
        if not path:
            return
        rect = self.canvas.scene_obj.itemsBoundingRect().adjusted(-40, -40, 40, 40)
        if rect.isNull():
            rect = QRectF(0, 0, 800, 600)
        img = QPixmap(int(max(400, rect.width())), int(max(300, rect.height())))
        img.fill(QColor("#0B1220"))
        painter = QPainter(img)
        painter.setRenderHint(QPainter.Antialiasing)
        self.canvas.scene_obj.render(painter, QRectF(img.rect()), rect)
        painter.end()
        img.save(path, "PNG")

    def shutdown(self) -> None:
        if self._discovery_worker and self._discovery_worker.isRunning():
            self._discovery_worker.request_stop()
            self._discovery_worker.quit()
            self._discovery_worker.wait(3000)
        if self._status_worker and self._status_worker.isRunning():
            self._status_worker.request_stop()
            self._status_worker.quit()
            self._status_worker.wait(3000)
