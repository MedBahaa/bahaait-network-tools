from typing import Any, Dict
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QGridLayout, QLabel, QVBoxLayout, QWidget
from utils.i18n import _


class _MiniKpiCard(QFrame):
    """Compact Quantum Midnight KPI card for the Intelligent Ping Monitoring overview bar."""

    def __init__(self, title: str, initial_value: str = "--", parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumHeight(58)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)

        self.value_label = QLabel(initial_value)
        self.value_label.setAlignment(Qt.AlignCenter)
        self.value_label.setStyleSheet(
            "font-size: 18px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px;"
        )

        self.title_label = QLabel(title.upper())
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet(
            "font-size: 10px; font-weight: 700; color: #94A3B8; letter-spacing: 0.8px; margin-bottom: 0px;"
        )

        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)

    def set_value(self, text: str, color: str = "#FFFFFF") -> None:
        self.value_label.setText(text)
        self.value_label.setStyleSheet(
            f"font-size: 18px; font-weight: 800; color: {color}; margin-bottom: 0px;"
        )


class MonitoringOverviewBar(QWidget):
    """2x4 KPI grid showing live fleet health, incidents, latency, packet loss, and uptime."""

    def __init__(self, parent=None):
        super().__init__(parent)
        grid = QGridLayout(self)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(10)

        self.total_card = _MiniKpiCard(_("mon_kpi_total", "Total Hosts"), "0", self)
        self.online_card = _MiniKpiCard(_("mon_kpi_online", "Online"), "0", self)
        self.degraded_card = _MiniKpiCard(_("mon_kpi_degraded", "Degraded"), "0", self)
        self.offline_card = _MiniKpiCard(_("mon_kpi_offline", "Offline"), "0", self)

        self.incidents_card = _MiniKpiCard(_("mon_kpi_incidents", "Active Incidents"), "0", self)
        self.latency_card = _MiniKpiCard(_("mon_kpi_avg_latency", "Avg Latency"), "-- ms", self)
        self.loss_card = _MiniKpiCard(_("mon_kpi_packet_loss", "Global Loss"), "0.0%", self)
        self.uptime_card = _MiniKpiCard(_("mon_kpi_uptime", "Global Uptime"), "100.0%", self)

        grid.addWidget(self.total_card, 0, 0)
        grid.addWidget(self.online_card, 0, 1)
        grid.addWidget(self.degraded_card, 0, 2)
        grid.addWidget(self.offline_card, 0, 3)

        grid.addWidget(self.incidents_card, 1, 0)
        grid.addWidget(self.latency_card, 1, 1)
        grid.addWidget(self.loss_card, 1, 2)
        grid.addWidget(self.uptime_card, 1, 3)

    def update_summary(self, summary: Dict[str, Any]) -> None:
        total = int(summary.get("total_hosts", 0))
        online = int(summary.get("online_hosts", 0))
        degraded = int(summary.get("degraded_hosts", 0))
        offline = int(summary.get("offline_hosts", 0))
        incidents = int(summary.get("active_incidents", 0))
        avg_lat = float(summary.get("avg_latency_ms", 0.0))
        loss = float(summary.get("global_packet_loss_pct", 0.0))
        uptime = float(summary.get("global_uptime_pct", 100.0))

        self.total_card.set_value(str(total), "#F1F5F9")
        self.online_card.set_value(str(online), "#10B981" if online > 0 else "#94A3B8")
        self.degraded_card.set_value(str(degraded), "#F59E0B" if degraded > 0 else "#94A3B8")
        self.offline_card.set_value(str(offline), "#F43F5E" if offline > 0 else "#94A3B8")

        self.incidents_card.set_value(str(incidents), "#F43F5E" if incidents > 0 else "#10B981")

        lat_color = "#10B981" if avg_lat < 80 else ("#F59E0B" if avg_lat < 150 else "#F43F5E")
        self.latency_card.set_value(f"{avg_lat:.1f} ms" if avg_lat > 0 else "-- ms", lat_color if avg_lat > 0 else "#94A3B8")

        loss_color = "#10B981" if loss == 0 else ("#F59E0B" if loss < 10.0 else "#F43F5E")
        self.loss_card.set_value(f"{loss:.1f}%", loss_color)

        up_color = "#10B981" if uptime >= 99.0 else ("#F59E0B" if uptime >= 95.0 else "#F43F5E")
        self.uptime_card.set_value(f"{uptime:.2f}%", up_color)
