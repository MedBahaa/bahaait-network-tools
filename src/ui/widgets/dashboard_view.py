from datetime import datetime, timedelta
import html
from typing import Any, Dict, List, Optional, Tuple

import pyqtgraph as pg
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ui.widgets.bandwidth_chart import BandwidthChart
from utils.db import DatabaseManager
from utils.i18n import _


_STATUS_COLORS = {
    "ONLINE": "#10B981",
    "DEGRADED": "#F59E0B",
    "OFFLINE": "#F43F5E",
    "UNKNOWN": "#94A3B8",
}


class KpiCard(QFrame):
    def __init__(self, emoji, title, value="--", parent=None):
        super().__init__(parent)
        self.setObjectName("KpiCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        val_layout = QHBoxLayout()
        val_layout.setSpacing(6)
        val_layout.setAlignment(Qt.AlignCenter)

        self.emoji_label = QLabel(emoji)
        self.emoji_label.setStyleSheet("font-size: 16px; margin-bottom: 0px;")

        self.value_label = QLabel(value)
        self.value_label.setObjectName("ValueLabel")
        self.value_label.setWordWrap(True)
        self.value_label.setStyleSheet("font-size: 18px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px;")

        val_layout.addWidget(self.emoji_label)
        val_layout.addWidget(self.value_label)

        self.title_label = QLabel(title.upper())
        self.title_label.setObjectName("SubTitle")
        self.title_label.setWordWrap(True)
        self.title_label.setStyleSheet(
            "font-size: 11px; color: #94A3B8; font-weight: 700; margin-bottom: 0px;"
        )
        self.title_label.setAlignment(Qt.AlignCenter)

        layout.addLayout(val_layout)
        layout.addWidget(self.title_label)

    def update_value(self, value, emoji=None):
        self.value_label.setText(str(value))
        if emoji:
            self.emoji_label.setText(emoji)


def _make_dash_plot() -> pg.PlotWidget:
    pw = pg.PlotWidget()
    pw.setBackground("#0F172A")
    pw.showGrid(x=True, y=True, alpha=0.15)
    pw.setMenuEnabled(False)
    pw.setMouseEnabled(x=False, y=False)
    pw.getAxis("bottom").setTextPen("#94A3B8")
    pw.getAxis("left").setTextPen("#94A3B8")
    pw.setMinimumHeight(195)
    return pw


class DashboardView(QWidget):
    """Upgraded v3.5.0 Infrastructure & Network Intelligence Dashboard."""

    def __init__(self, logger, config_manager=None, db: Optional[DatabaseManager] = None):
        super().__init__()
        self.logger = logger
        self.config = config_manager
        self.db = db or DatabaseManager()

        # Main Layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(24, 22, 24, 20)
        self.main_layout.setSpacing(14)

        # Header Title
        header = QLabel(_("dash_title", "Network Dashboard"))
        header.setObjectName("Title")
        header.setStyleSheet("font-size: 26px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px;")
        self.main_layout.addWidget(header)

        # Scroll Area for responsiveness
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("background: transparent;")

        scroll_content = QWidget()
        scroll_content.setStyleSheet("background: transparent;")
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(0, 0, 10, 0)
        scroll_layout.setSpacing(16)

        # 1. 10 KPI Cards Grid (2 rows x 5 columns)
        kpi_grid = QGridLayout()
        kpi_grid.setSpacing(12)

        self.hosts_kpi = KpiCard("🟢", _("dash_hosts_up", "Hosts UP"), "--/--", self)
        self.snmp_devices_kpi = KpiCard("🖥️", _("dash_snmp_devices", "SNMP Devices"), "0", self)
        self.interfaces_kpi = KpiCard("🔌", _("dash_interfaces", "Interfaces UP/DN"), "0/0", self)
        self.anomalies_kpi = KpiCard("🧠", _("dash_anomalies", "Active Anomalies"), "0", self)
        self.syslog_kpi = KpiCard("📜", _("dash_syslog_alerts", "Syslog Alerts"), "0", self)

        self.avg_cpu_kpi = KpiCard("⚙️", _("dash_avg_cpu", "Avg Infra CPU"), "--", self)
        self.avg_mem_kpi = KpiCard("💾", _("dash_avg_mem", "Avg Infra RAM"), "--", self)
        self.poe_kpi = KpiCard("⚡", _("dash_poe_usage", "PoE Utilization"), "--", self)
        self.download_kpi = KpiCard("📊", _("dash_download", "Download"), "-- Mbps", self)
        self.latency_kpi = KpiCard("⏱️", _("dash_latency", "Latency"), "-- ms", self)

        self.kpi_cards = [
            self.hosts_kpi,
            self.snmp_devices_kpi,
            self.interfaces_kpi,
            self.anomalies_kpi,
            self.syslog_kpi,
            self.avg_cpu_kpi,
            self.avg_mem_kpi,
            self.poe_kpi,
            self.download_kpi,
            self.latency_kpi,
        ]
        for idx, card in enumerate(self.kpi_cards):
            r, c = divmod(idx, 5)
            kpi_grid.addWidget(card, r, c)
        for c in range(5):
            kpi_grid.setColumnStretch(c, 1)
        scroll_layout.addLayout(kpi_grid)

        # 2. 8 Charts / Visuals in 2-column grid cards
        charts_grid = QGridLayout()
        charts_grid.setSpacing(14)
        charts_grid.setColumnStretch(0, 1)
        charts_grid.setColumnStretch(1, 1)

        # Chart 1: Real-time Network Throughput (BandwidthChart preserved)
        self.bandwidth_chart = BandwidthChart()
        self.bandwidth_chart.setMinimumHeight(195)
        charts_grid.addWidget(
            self._wrap_chart_card(_("dash_throughput", "NETWORK THROUGHPUT"), self.bandwidth_chart), 0, 0
        )

        # Chart 2: Infrastructure CPU Trend
        self.cpu_plot = _make_dash_plot()
        charts_grid.addWidget(
            self._wrap_chart_card(_("dash_chart_cpu", "INFRASTRUCTURE CPU TREND (%)"), self.cpu_plot), 0, 1
        )

        # Chart 3: Infrastructure Memory Trend
        self.mem_plot = _make_dash_plot()
        charts_grid.addWidget(
            self._wrap_chart_card(_("dash_chart_mem", "INFRASTRUCTURE MEMORY TREND (%)"), self.mem_plot), 1, 0
        )

        # Chart 4: Aggregate Interface Traffic In/Out
        self.traffic_plot = _make_dash_plot()
        self.traffic_plot.addLegend(offset=(8, 8))
        charts_grid.addWidget(
            self._wrap_chart_card(_("dash_chart_if_traffic", "AGGREGATE INTERFACE TRAFFIC (Mbps)"), self.traffic_plot), 1, 1
        )

        # Chart 5: Top Utilized Interfaces
        self.top_ifaces_plot = _make_dash_plot()
        charts_grid.addWidget(
            self._wrap_chart_card(_("dash_chart_top_ifaces", "TOP UTILIZED INTERFACES (%)"), self.top_ifaces_plot), 2, 0
        )

        # Chart 6: SNMP Device Health Status Breakdown
        self.dev_health_plot = _make_dash_plot()
        charts_grid.addWidget(
            self._wrap_chart_card(_("dash_chart_dev_health", "SNMP DEVICE HEALTH STATUS"), self.dev_health_plot), 2, 1
        )

        # Chart 7: Syslog Severity Breakdown
        self.syslog_sev_plot = _make_dash_plot()
        charts_grid.addWidget(
            self._wrap_chart_card(_("dash_chart_syslog_sev", "SYSLOG SEVERITY DISTRIBUTION"), self.syslog_sev_plot), 3, 0
        )

        # Chart 8: Active Intelligence Anomalies by Type
        self.anomalies_plot = _make_dash_plot()
        charts_grid.addWidget(
            self._wrap_chart_card(_("dash_chart_anomalies_type", "ACTIVE ANOMALIES BY TYPE"), self.anomalies_plot), 3, 1
        )

        scroll_layout.addLayout(charts_grid)

        # 3. SNMP Infrastructure Inventory Table
        inv_card = QFrame()
        inv_card.setObjectName("PanelCard")
        inv_lay = QVBoxLayout(inv_card)
        inv_lay.setContentsMargins(18, 14, 18, 14)
        inv_lay.setSpacing(8)
        inv_hdr = QLabel(_("dash_snmp_inventory", "SNMP INFRASTRUCTURE INVENTORY"))
        inv_hdr.setObjectName("SectionHeader")
        inv_hdr.setStyleSheet("font-size: 12px; font-weight: bold; margin-bottom: 0px;")
        inv_lay.addWidget(inv_hdr)

        self.inventory_table = QTableWidget(0, 7)
        self.inventory_table.setHorizontalHeaderLabels([
            _("snmp_col_name", "Device Name"),
            "IP",
            _("snmp_col_vendor_model", "Vendor / Model"),
            _("snmp_col_status", "Status"),
            _("snmp_col_cpu", "CPU %"),
            _("snmp_col_mem", "RAM %"),
            _("snmp_col_ifaces", "Interfaces"),
        ])
        self.inventory_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.inventory_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.inventory_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.inventory_table.setAlternatingRowColors(True)
        self.inventory_table.verticalHeader().setVisible(False)
        self.inventory_table.verticalHeader().setDefaultSectionSize(32)
        ih = self.inventory_table.horizontalHeader()
        ih.setSectionResizeMode(0, QHeaderView.Stretch)
        ih.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        ih.setSectionResizeMode(2, QHeaderView.Stretch)
        ih.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        ih.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        ih.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        ih.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.inventory_table.setMinimumHeight(140)
        self.inventory_table.setMaximumHeight(220)
        inv_lay.addWidget(self.inventory_table)
        scroll_layout.addWidget(inv_card)

        # 4. Alerts & Sites Summary Double Columns (preserved)
        bottom_cols = QHBoxLayout()
        bottom_cols.setSpacing(15)

        self.alerts_card = QFrame()
        self.alerts_card.setObjectName("PanelCard")
        self.alerts_layout = QVBoxLayout(self.alerts_card)
        self.alerts_layout.setContentsMargins(20, 16, 20, 16)
        self.alerts_layout.setSpacing(10)

        alerts_header = QLabel(_("dash_latest_alerts", "Latest Alerts"))
        alerts_header.setObjectName("SectionHeader")
        alerts_header.setStyleSheet("font-size: 13px; font-weight: bold; margin-bottom: 0px;")
        self.alerts_layout.addWidget(alerts_header)

        self.alerts_content_layout = QVBoxLayout()
        self.alerts_content_layout.setSpacing(6)
        self.alerts_layout.addLayout(self.alerts_content_layout)
        self.alerts_layout.addStretch()

        self.sites_card = QFrame()
        self.sites_card.setObjectName("PanelCard")
        self.sites_layout = QVBoxLayout(self.sites_card)
        self.sites_layout.setContentsMargins(20, 16, 20, 16)
        self.sites_layout.setSpacing(10)

        sites_header = QLabel(_("dash_sites_summary", "Equipment Summary by Site"))
        sites_header.setObjectName("SectionHeader")
        sites_header.setStyleSheet("font-size: 13px; font-weight: bold; margin-bottom: 0px;")
        self.sites_layout.addWidget(sites_header)

        self.sites_content_layout = QVBoxLayout()
        self.sites_content_layout.setSpacing(6)
        self.sites_layout.addLayout(self.sites_content_layout)
        self.sites_layout.addStretch()

        bottom_cols.addWidget(self.alerts_card, 1)
        bottom_cols.addWidget(self.sites_card, 1)
        scroll_layout.addLayout(bottom_cols)

        # 5. Bottom Speedtest Status Bar (preserved)
        self.bottom_bar = QFrame()
        self.bottom_bar.setObjectName("PanelCard")
        self.bottom_bar.setFixedHeight(45)
        self.bottom_layout = QHBoxLayout(self.bottom_bar)
        self.bottom_layout.setContentsMargins(20, 0, 20, 0)
        self.bottom_layout.setAlignment(Qt.AlignVCenter)

        self.bottom_label = QLabel()
        self.bottom_label.setStyleSheet("color: #E2E8F0; font-size: 13px; font-weight: bold; margin-bottom: 0px;")
        self.bottom_layout.addWidget(self.bottom_label, 1)

        scroll_layout.addWidget(self.bottom_bar)

        scroll.setWidget(scroll_content)
        self.main_layout.addWidget(scroll)

        # Periodic Info Updates (skip background polling when tab is hidden)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._on_timer_tick)
        self.timer.start(10000)

        self.update_info()

    def _on_timer_tick(self):
        if self.isVisible():
            self.update_info()

    @staticmethod
    def _wrap_chart_card(title: str, chart_widget: QWidget) -> QFrame:
        card = QFrame()
        card.setObjectName("PanelCard")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(16, 14, 16, 14)
        cl.setSpacing(8)
        hdr = QLabel(title)
        hdr.setObjectName("SubTitle")
        hdr.setWordWrap(True)
        hdr.setStyleSheet("font-size: 11px; color: #94A3B8; font-weight: 800; margin-bottom: 0px;")
        cl.addWidget(hdr)
        cl.addWidget(chart_widget)
        return card

    def showEvent(self, event):
        super().showEvent(event)
        self.update_info()

    def _draw_bars(
        self,
        plot: pg.PlotWidget,
        labels: List[str],
        values: List[float],
        brushes: Any,
        y_max: Optional[float] = None,
    ) -> None:
        plot.clear()
        if not labels:
            plot.getAxis("bottom").setTicks([[]])
            return
        xs = list(range(len(labels)))
        bar = pg.BarGraphItem(x=xs, height=values, width=0.55, brushes=brushes)
        plot.addItem(bar)
        plot.getAxis("bottom").setTicks([list(zip(xs, labels))])
        if y_max is not None:
            plot.setYRange(0, y_max)
        else:
            plot.setYRange(0, max(max(values) * 1.2, 5.0))

    def _update_infra_visuals(self) -> None:
        devices = self.db.get_snmp_devices(enabled_only=False)
        snaps: Dict[int, Dict[str, Any]] = {}
        try:
            parent_win = self.window()
            if parent_win is not None and getattr(parent_win, "snmp_view", None) is not None:
                snaps = parent_win.snmp_view.get_live_snapshots()
        except Exception:
            snaps = {}

        online_cnt = degraded_cnt = offline_cnt = unknown_cnt = 0
        cpu_latest: List[float] = []
        mem_latest: List[float] = []
        poe_utils: List[float] = []
        up_ifaces_total = 0
        down_ifaces_total = 0

        cpu_buckets: List[List[float]] = []
        mem_buckets: List[List[float]] = []
        in_buckets: List[List[float]] = []
        out_buckets: List[List[float]] = []
        top_iface_items: List[Tuple[str, float]] = []

        self.inventory_table.setRowCount(0)
        for dev in devices:
            did = int(dev["id"])
            snap = snaps.get(did) or {}
            st = str(snap.get("status") or dev.get("status") or "UNKNOWN").upper()
            if st == "ONLINE":
                online_cnt += 1
            elif st == "DEGRADED":
                degraded_cnt += 1
            elif st == "OFFLINE":
                offline_cnt += 1
            else:
                unknown_cnt += 1

            mrows = self.db.get_snmp_metrics(did, limit=120)
            dev_m: Dict[str, float] = {}
            d_cpu: List[float] = []
            d_mem: List[float] = []
            d_in: List[float] = []
            d_out: List[float] = []
            for r in mrows:
                mn = r["metric_name"]
                val = float(r["metric_value"])
                dev_m[mn] = val
                if mn == "cpu_pct":
                    d_cpu.append(val)
                elif mn == "memory_pct":
                    d_mem.append(val)
                elif mn == "total_in_mbps":
                    d_in.append(val)
                elif mn == "total_out_mbps":
                    d_out.append(val)

            for idx_s, val_s in enumerate(d_cpu[-60:]):
                if idx_s >= len(cpu_buckets):
                    cpu_buckets.append([])
                cpu_buckets[idx_s].append(val_s)
            for idx_s, val_s in enumerate(d_mem[-60:]):
                if idx_s >= len(mem_buckets):
                    mem_buckets.append([])
                mem_buckets[idx_s].append(val_s)
            for idx_s, val_s in enumerate(d_in[-60:]):
                if idx_s >= len(in_buckets):
                    in_buckets.append([])
                in_buckets[idx_s].append(val_s)
            for idx_s, val_s in enumerate(d_out[-60:]):
                if idx_s >= len(out_buckets):
                    out_buckets.append([])
                out_buckets[idx_s].append(val_s)

            for mk, mv in (snap.get("metrics") or {}).items():
                if isinstance(mv, (int, float)) and not isinstance(mv, bool):
                    dev_m[mk] = float(mv)

            if "cpu_pct" in dev_m:
                cpu_latest.append(dev_m["cpu_pct"])
            if "memory_pct" in dev_m:
                mem_latest.append(dev_m["memory_pct"])
            if "poe_utilization_pct" in dev_m:
                poe_utils.append(dev_m["poe_utilization_pct"])

            ifaces = self.db.get_snmp_interfaces(did)
            up_if = sum(1 for i in ifaces if str(i.get("oper_status")).upper() == "UP")
            dn_if = sum(1 for i in ifaces if str(i.get("oper_status")).upper() == "DOWN")
            up_ifaces_total += up_if
            down_ifaces_total += dn_if

            # Latest utilization per interface
            meas = self.db.get_interface_measurements(device_id=did, limit=100)
            by_iid: Dict[int, float] = {}
            for mr in meas:
                by_iid[int(mr["interface_id"])] = float(mr.get("utilization_pct") or 0.0)
            for meta in ifaces:
                util_v = by_iid.get(int(meta["id"]), 0.0)
                if util_v > 0:
                    lbl = f"{dev['name'][:6]}:{meta.get('name') or meta['if_index']}"
                    top_iface_items.append((lbl[:14], util_v))

            # Populate inventory row
            r_idx = self.inventory_table.rowCount()
            self.inventory_table.insertRow(r_idx)
            self.inventory_table.setItem(r_idx, 0, QTableWidgetItem(dev["name"]))
            self.inventory_table.setItem(r_idx, 1, QTableWidgetItem(dev["ip_address"]))
            self.inventory_table.setItem(
                r_idx, 2, QTableWidgetItem(f"{dev.get('vendor', 'Generic')} {dev.get('model', '')}".strip())
            )
            st_item = QTableWidgetItem(st)
            st_item.setForeground(QColor(_STATUS_COLORS.get(st, "#94A3B8")))
            self.inventory_table.setItem(r_idx, 3, st_item)
            self.inventory_table.setItem(r_idx, 4, QTableWidgetItem(f"{dev_m['cpu_pct']:.1f}%" if "cpu_pct" in dev_m else "--"))
            self.inventory_table.setItem(r_idx, 5, QTableWidgetItem(f"{dev_m['memory_pct']:.1f}%" if "memory_pct" in dev_m else "--"))
            self.inventory_table.setItem(r_idx, 6, QTableWidgetItem(f"{up_if}/{len(ifaces)}" if ifaces else "--"))

        # Syslog alerts in last 24h (severity <= Error=3)
        since_24h = datetime.utcnow() - timedelta(hours=24)
        syslog_rows = self.db.get_syslog_events(since=since_24h, limit=500)
        syslog_alerts = sum(1 for s in syslog_rows if int(s.get("severity", 6)) <= 3)

        # Open anomalies
        anoms = [
            a for a in self.db.get_network_anomalies(limit=500)
            if a.get("status") in ("ACTIVE", "ACKNOWLEDGED")
        ]

        # Update SNMP/NOC KPIs
        snmp_emoji = "🖥️" if degraded_cnt == 0 and offline_cnt == 0 else ("🟠" if offline_cnt == 0 else "🔴")
        self.snmp_devices_kpi.update_value(f"{online_cnt}/{len(devices)}", snmp_emoji)
        self.interfaces_kpi.update_value(f"{up_ifaces_total}/{down_ifaces_total}")
        self.anomalies_kpi.update_value(str(len(anoms)), "🔴" if anoms else "🟢")
        self.syslog_kpi.update_value(str(syslog_alerts))
        self.avg_cpu_kpi.update_value(f"{sum(cpu_latest)/len(cpu_latest):.1f}%" if cpu_latest else "--")
        self.avg_mem_kpi.update_value(f"{sum(mem_latest)/len(mem_latest):.1f}%" if mem_latest else "--")
        self.poe_kpi.update_value(f"{sum(poe_utils)/len(poe_utils):.1f}%" if poe_utils else "N/A")

        cpu_series = [sum(b) / len(b) for b in cpu_buckets if b]
        mem_series = [sum(b) / len(b) for b in mem_buckets if b]
        in_series = [sum(b) for b in in_buckets if b]
        out_series = [sum(b) for b in out_buckets if b]

        # Update Chart 2: CPU Trend
        self.cpu_plot.clear()
        if cpu_series:
            pts = cpu_series[-60:]
            self.cpu_plot.plot(list(range(len(pts))), pts, pen=pg.mkPen("#06B6D4", width=2))
            self.cpu_plot.setYRange(0, 100)

        # Update Chart 3: Memory Trend
        self.mem_plot.clear()
        if mem_series:
            pts = mem_series[-60:]
            self.mem_plot.plot(list(range(len(pts))), pts, pen=pg.mkPen("#6366F1", width=2))
            self.mem_plot.setYRange(0, 100)

        # Update Chart 4: Aggregate Interface Traffic
        self.traffic_plot.clear()
        if in_series or out_series:
            if in_series:
                pts_in = in_series[-60:]
                self.traffic_plot.plot(list(range(len(pts_in))), pts_in, name="IN", pen=pg.mkPen("#10B981", width=2))
            if out_series:
                pts_out = out_series[-60:]
                self.traffic_plot.plot(list(range(len(pts_out))), pts_out, name="OUT", pen=pg.mkPen("#6366F1", width=2))

        # Update Chart 5: Top Utilized Interfaces
        top_sorted = sorted(top_iface_items, key=lambda kv: kv[1], reverse=True)[:5]
        self._draw_bars(
            self.top_ifaces_plot,
            [x[0] for x in top_sorted],
            [x[1] for x in top_sorted],
            ["#F59E0B" if x[1] >= 80.0 else "#06B6D4" for x in top_sorted],
            y_max=100.0,
        )

        # Update Chart 6: Device Health Status Breakdown
        self._draw_bars(
            self.dev_health_plot,
            ["Online", "Degraded", "Offline", "Unknown"],
            [float(online_cnt), float(degraded_cnt), float(offline_cnt), float(unknown_cnt)],
            ["#10B981", "#F59E0B", "#F43F5E", "#64748B"],
        )

        # Update Chart 7: Syslog Severity Breakdown
        sev_crit = sum(1 for s in syslog_rows if int(s.get("severity", 6)) <= 3)
        sev_warn = sum(1 for s in syslog_rows if int(s.get("severity", 6)) == 4)
        sev_info = sum(1 for s in syslog_rows if int(s.get("severity", 6)) >= 5)
        self._draw_bars(
            self.syslog_sev_plot,
            ["Crit / Err", "Warning", "Notice / Info"],
            [float(sev_crit), float(sev_warn), float(sev_info)],
            ["#F43F5E", "#F59E0B", "#38BDF8"],
        )

        # Update Chart 8: Active Intelligence Anomalies by Type
        by_type: Dict[str, int] = {}
        for a in anoms:
            et = str(a.get("event_type", "OTHER"))[:14]
            by_type[et] = by_type.get(et, 0) + 1
        top_anom = sorted(by_type.items(), key=lambda kv: kv[1], reverse=True)[:5]
        self._draw_bars(
            self.anomalies_plot,
            [k for k, _ in top_anom],
            [float(v) for _, v in top_anom],
            ["#F43F5E"] * len(top_anom),
        )

    def update_info(self):
        try:
            # 1. Update Hosts UP KPI
            hosts_sum = self.db.get_hosts_status_summary()
            total_hosts = hosts_sum["total"]
            up_hosts = hosts_sum["up"]
            hosts_emoji = "🟢" if hosts_sum["down"] == 0 and total_hosts > 0 else "🔴" if total_hosts > 0 else "🟢"
            self.hosts_kpi.update_value(f"{up_hosts}/{total_hosts}", hosts_emoji)

            # 2. Update Latency KPI
            avg_lat = self.db.get_average_latency()
            self.latency_kpi.update_value(f"{avg_lat} ms" if avg_lat > 0 else "0 ms")

            # 3. Update Speedtest KPI & Bottom Bar
            st = self.db.get_latest_speedtest()
            if st:
                download_val = st["download"]
                self.download_kpi.update_value(f"{int(download_val)} Mbps")
                down_speed = int(st["download"])
                up_speed = int(st["upload"])
                time_elapsed = st["time_str"]
                self.bottom_label.setText(
                    f"⏱ {_('dash_last_speedtest', 'Dernier Speed Test')} : {down_speed}↓ / {up_speed}↑ Mbps   •   {time_elapsed}"
                )
            else:
                self.download_kpi.update_value("0 Mbps")
                self.bottom_label.setText(f"⏱ {_('dash_no_speedtest', 'Aucun Speed Test enregistré')}")

            # 4. Update Infrastructure KPIs, 8 Visuals & Inventory
            self._update_infra_visuals()

            # 5. Update Alerts List (Double Column Left)
            while self.alerts_content_layout.count():
                child = self.alerts_content_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()

            alerts = self.db.get_latest_alerts(limit=3)
            if not alerts:
                no_alert = QLabel("— " + _("dash_no_alerts", "Pas d'alertes récentes"))
                no_alert.setWordWrap(True)
                no_alert.setStyleSheet("color: #94A3B8; font-style: italic; font-size: 12px; margin-bottom: 0px;")
                self.alerts_content_layout.addWidget(no_alert)
            else:
                for a in alerts:
                    color = "#10B981" if a["status"] == "UP" else "#F43F5E"
                    status_text = f"<span style='color: {color}; font-weight: bold;'>{html.escape(str(a['status']))}</span>"
                    item_label = QLabel(
                        f"— {html.escape(str(a['timestamp']))} {html.escape(str(a['host']))} {status_text}"
                    )
                    item_label.setWordWrap(True)
                    item_label.setStyleSheet("color: #E2E8F0; font-size: 12px; margin-bottom: 0px;")
                    self.alerts_content_layout.addWidget(item_label)

            # 6. Update Sites Summary List (Double Column Right)
            while self.sites_content_layout.count():
                child = self.sites_content_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()

            sites_data = self.config.get("sites", []) if self.config else []
            if not sites_data:
                no_site = QLabel("— " + _("dash_no_sites", "Aucun équipement configuré"))
                no_site.setWordWrap(True)
                no_site.setStyleSheet("color: #94A3B8; font-style: italic; font-size: 12px; margin-bottom: 0px;")
                self.sites_content_layout.addWidget(no_site)
            else:
                site_counts = {}
                other_lbl = _("dash_other", "Other")
                for s in sites_data:
                    s_name = s.get("site", other_lbl) or other_lbl
                    site_counts[s_name] = site_counts.get(s_name, 0) + 1

                sorted_sites = sorted(site_counts.items(), key=lambda x: x[1], reverse=True)[:3]
                for site, count in sorted_sites:
                    lbl = QLabel(f"• {site} : {count} {_('dash_equipments', 'équipement(s)')}")
                    lbl.setWordWrap(True)
                    lbl.setStyleSheet("color: #E2E8F0; font-size: 12px; margin-bottom: 0px;")
                    self.sites_content_layout.addWidget(lbl)

        except Exception as e:
            self.logger.error(f"Error updating dashboard info: {e}")

    def shutdown(self) -> None:
        if hasattr(self, "timer") and self.timer is not None:
            self.timer.stop()
        if hasattr(self, "bandwidth_chart") and getattr(self.bandwidth_chart, "timer", None) is not None:
            self.bandwidth_chart.timer.stop()
