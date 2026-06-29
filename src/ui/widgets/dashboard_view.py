from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                              QFrame, QGridLayout, QScrollArea)
from PySide6.QtCore import Qt, QTimer
from core.tools import NetworkTools
from ui.widgets.bandwidth_chart import BandwidthChart
from utils.db import DatabaseManager
from utils.i18n import _
import os

class KpiCard(QFrame):
    def __init__(self, emoji, title, value="--", parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 12, 15, 12)
        layout.setSpacing(4)
        
        # Value row (horizontal to put emoji + value)
        val_layout = QHBoxLayout()
        val_layout.setSpacing(8)
        val_layout.setAlignment(Qt.AlignCenter)
        
        self.emoji_label = QLabel(emoji)
        self.emoji_label.setStyleSheet("font-size: 22px; margin-bottom: 0px;")
        
        self.value_label = QLabel(value)
        self.value_label.setObjectName("ValueLabel")
        self.value_label.setStyleSheet("font-size: 22px; font-weight: 800; color: #FFFFFF; margin-bottom: 0px;")
        
        val_layout.addWidget(self.emoji_label)
        val_layout.addWidget(self.value_label)
        
        # Title
        self.title_label = QLabel(title)
        self.title_label.setObjectName("SubTitle")
        self.title_label.setStyleSheet("font-size: 11px; color: #94A3B8; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 0px;")
        self.title_label.setAlignment(Qt.AlignCenter)
        
        layout.addLayout(val_layout)
        layout.addWidget(self.title_label)
        
    def update_value(self, value, emoji=None):
        self.value_label.setText(value)
        if emoji:
            self.emoji_label.setText(emoji)


class DashboardView(QWidget):
    def __init__(self, logger, config_manager=None):
        super().__init__()
        self.logger = logger
        self.config = config_manager
        self.db = DatabaseManager()
        
        # Main Layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(30, 30, 30, 30)
        self.main_layout.setSpacing(20)
        
        # Header Title
        header = QLabel(_("dash_title", "Network Dashboard"))
        header.setObjectName("Title")
        self.main_layout.addWidget(header)
        
        # Scroll Area for responsiveness on smaller screens
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
        scroll_layout.setSpacing(20)
        
        # 1. KPIs Row
        kpis_layout = QHBoxLayout()
        kpis_layout.setSpacing(15)
        
        self.hosts_kpi = KpiCard("🟢", _("dash_hosts_up", "Hosts UP"), "--/--", self)
        self.download_kpi = KpiCard("📊", _("dash_download", "Download"), "-- Mbps", self)
        self.latency_kpi = KpiCard("⏱️", _("dash_latency", "Latence"), "-- ms", self)
        
        kpis_layout.addWidget(self.hosts_kpi)
        kpis_layout.addWidget(self.download_kpi)
        kpis_layout.addWidget(self.latency_kpi)
        scroll_layout.addLayout(kpis_layout)
        
        # 2. Real-time Bandwidth Chart
        chart_card = QFrame()
        chart_card.setObjectName("Card")
        chart_layout = QVBoxLayout(chart_card)
        chart_layout.setContentsMargins(25, 20, 25, 20)
        chart_layout.setSpacing(10)
        
        chart_header = QLabel(_("dash_throughput", "NETWORK THROUGHPUT"))
        chart_header.setObjectName("SubTitle")
        chart_layout.addWidget(chart_header)
        
        self.bandwidth_chart = BandwidthChart()
        self.bandwidth_chart.setMinimumHeight(280)
        chart_layout.addWidget(self.bandwidth_chart)
        
        scroll_layout.addWidget(chart_card)
        
        # 3. Bottom Double Columns (Alerts & Sites Summary)
        bottom_cols = QHBoxLayout()
        bottom_cols.setSpacing(15)
        
        # 3.1 Alerts Card (Left)
        self.alerts_card = QFrame()
        self.alerts_card.setObjectName("Card")
        self.alerts_layout = QVBoxLayout(self.alerts_card)
        self.alerts_layout.setContentsMargins(22, 20, 22, 20)
        self.alerts_layout.setSpacing(12)
        
        alerts_header = QLabel("🔔 " + _("dash_latest_alerts", "Dernières Alertes"))
        alerts_header.setObjectName("SectionHeader")
        alerts_header.setStyleSheet("font-size: 13px; font-weight: bold; margin-bottom: 0px;")
        self.alerts_layout.addWidget(alerts_header)
        
        self.alerts_content_layout = QVBoxLayout()
        self.alerts_content_layout.setSpacing(6)
        self.alerts_layout.addLayout(self.alerts_content_layout)
        self.alerts_layout.addStretch()
        
        # 3.2 Sites Summary Card (Right)
        self.sites_card = QFrame()
        self.sites_card.setObjectName("Card")
        self.sites_layout = QVBoxLayout(self.sites_card)
        self.sites_layout.setContentsMargins(22, 20, 22, 20)
        self.sites_layout.setSpacing(12)
        
        sites_header = QLabel("📋 " + _("dash_sites_summary", "Résumé Équipements par Site"))
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
        
        # 4. Bottom Speedtest Status Bar
        self.bottom_bar = QFrame()
        self.bottom_bar.setObjectName("Card")
        self.bottom_bar.setFixedHeight(45)
        self.bottom_layout = QHBoxLayout(self.bottom_bar)
        self.bottom_layout.setContentsMargins(20, 0, 20, 0)
        self.bottom_layout.setAlignment(Qt.AlignVertical_Mask)
        
        self.bottom_label = QLabel()
        self.bottom_label.setStyleSheet("color: #E2E8F0; font-size: 13px; font-weight: bold; margin-bottom: 0px;")
        self.bottom_layout.addWidget(self.bottom_label, 1)
        
        scroll_layout.addWidget(self.bottom_bar)
        
        # Setup Scroll Widget
        scroll.setWidget(scroll_content)
        self.main_layout.addWidget(scroll)
        
        # Periodic Info Updates (Timer)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_info)
        self.timer.start(10000) # Every 10 seconds
        
        # Initial Update
        self.update_info()

    def showEvent(self, event):
        super().showEvent(event)
        self.update_info()

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
            

            
            # 4. Update Speedtest KPI & Bottom Bar
            st = self.db.get_latest_speedtest()
            if st:
                download_val = st["download"]
                self.download_kpi.update_value(f"{int(download_val)} Mbps")
                
                # Bottom Bar Text
                down_speed = int(st["download"])
                up_speed = int(st["upload"])
                time_elapsed = st["time_str"]
                self.bottom_label.setText(
                    f"⏱️ {_('dash_last_speedtest', 'Dernier Speed Test')} : {down_speed}↓ / {up_speed}↑ Mbps   •   {time_elapsed}"
                )
            else:
                self.download_kpi.update_value("0 Mbps")
                self.bottom_label.setText(f"⏱️ {_('dash_no_speedtest', 'Aucun Speed Test enregistré')}")
                
            # 5. Update Alerts List (Double Column Left)
            while self.alerts_content_layout.count():
                child = self.alerts_content_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()
            
            alerts = self.db.get_latest_alerts(limit=3)
            if not alerts:
                no_alert = QLabel("— " + _("dash_no_alerts", "Pas d'alertes récentes"))
                no_alert.setStyleSheet("color: #64748B; font-style: italic; font-size: 12px; margin-bottom: 0px;")
                self.alerts_content_layout.addWidget(no_alert)
            else:
                for a in alerts:
                    color = "#10B981" if a["status"] == "UP" else "#F43F5E"
                    status_text = f"<span style='color: {color}; font-weight: bold;'>{a['status']}</span>"
                    item_label = QLabel(f"— {a['timestamp']} {a['host']} {status_text}")
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
                no_site.setStyleSheet("color: #64748B; font-style: italic; font-size: 12px; margin-bottom: 0px;")
                self.sites_content_layout.addWidget(no_site)
            else:
                site_counts = {}
                for s in sites_data:
                    s_name = s.get("site", "Autre") or "Autre"
                    site_counts[s_name] = site_counts.get(s_name, 0) + 1
                    
                # Add to layout (limit to 3 for neat visual matching)
                sorted_sites = sorted(site_counts.items(), key=lambda x: x[1], reverse=True)[:3]
                for site, count in sorted_sites:
                    lbl = QLabel(f"• {site} : {count} {_('dash_equipments', 'équipement(s)')}")
                    lbl.setStyleSheet("color: #E2E8F0; font-size: 12px; margin-bottom: 0px;")
                    self.sites_content_layout.addWidget(lbl)
                    
        except Exception as e:
            self.logger.error(f"Error updating dashboard info: {e}")
