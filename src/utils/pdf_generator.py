from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from datetime import datetime
import os
from utils.i18n import _

class PDFReportGenerator:
    def __init__(self, filename="BahaaIT_Network_Report.pdf"):
        self.filename = filename
        self.styles = getSampleStyleSheet()
        
        # Add a custom title style
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#6366F1'),
            alignment=1 # Center
        ))
        
        self.styles.add(ParagraphStyle(
            name='Subtitle',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.gray,
            alignment=1,
            spaceAfter=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='LogLine',
            parent=self.styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#334155'),
            spaceAfter=2
        ))

        # New styles for Speedtest Report
        self.styles.add(ParagraphStyle(
            name='HeaderAppTitle',
            parent=self.styles['Normal'],
            fontSize=15,
            leading=17,
            textColor=colors.HexColor('#1E293B'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='HeaderMeta',
            parent=self.styles['Normal'],
            fontSize=8,
            leading=12,
            alignment=2 # Right
        ))
        
        self.styles.add(ParagraphStyle(
            name='KPITitle',
            parent=self.styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#64748B'),
            alignment=1, # Center
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='KPIValue',
            parent=self.styles['Normal'],
            fontSize=16,
            leading=18,
            alignment=1, # Center
            fontName='Helvetica'
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=11,
            leading=13,
            textColor=colors.HexColor('#1E293B'),
            fontName='Helvetica-Bold',
            spaceBefore=12,
            spaceAfter=6
        ))
        
        self.styles.add(ParagraphStyle(
            name='TableHeader',
            parent=self.styles['Normal'],
            fontSize=9,
            leading=11,
            textColor=colors.whitesmoke,
            alignment=1, # Center
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='TableText',
            parent=self.styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#334155'),
            fontName='Helvetica'
        ))
        
        self.styles.add(ParagraphStyle(
            name='TableTextCenter',
            parent=self.styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#334155'),
            alignment=1, # Center
            fontName='Helvetica'
        ))
        
        self.styles.add(ParagraphStyle(
            name='MetaTitle',
            parent=self.styles['Normal'],
            fontSize=9,
            leading=11,
            textColor=colors.HexColor('#1E293B'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='MetaText',
            parent=self.styles['Normal'],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#475569'),
            fontName='Helvetica'
        ))

    def generate_monitor_report(self, data, save_path=None, event_log_text=None):
        if not data:
            return False, "Aucune donnée disponible pour le rapport."

        if not save_path:
            save_path = os.path.join(os.path.expanduser("~"), "Desktop", self.filename)
            
        # Imports requises pour le graphique de latence par équipement
        from reportlab.graphics.shapes import Drawing, Rect, String as DString, Line, Circle
        import sys
        
        # Configuration du document
        doc = SimpleDocTemplate(
            save_path,
            pagesize=letter,
            title="BahaaIT Network Diagnostics Report",
            author="BahaaIT Network Tools",
            creator="BahaaIT Network Tools",
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=54
        )
        elements = []
        
        # Logo & Header
        if getattr(sys, 'frozen', False):
            logo_path = os.path.join(sys._MEIPASS, "src", "assets", "logo.png")
        else:
            logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png"))
            
        # Header Layout
        logo_cell = ""
        if os.path.exists(logo_path):
            logo_img = Image(logo_path, width=32, height=32)
            logo_img.hAlign = 'LEFT'
            
            title_p = Paragraph("<font size='15' color='#1E293B'><b>BahaaIT Network Tools</b></font>", self.styles['HeaderAppTitle'])
            logo_cell = Table([[logo_img, title_p]], colWidths=[40, 260])
            logo_cell.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('LEFTPADDING', (0,0), (-1,-1), 0),
                ('RIGHTPADDING', (0,0), (-1,-1), 0),
                ('TOPPADDING', (0,0), (-1,-1), 0),
                ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ]))
        else:
            logo_cell = Paragraph("<font size='15' color='#1E293B'><b>BahaaIT Network Tools</b></font>", self.styles['HeaderAppTitle'])
            
        right_p = Paragraph(
            f"<font size='11' color='#6366F1'><b>Rapport de Surveillance Réseau</b></font><br/>"
            f"<font size='8' color='#64748B'>Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</font>",
            self.styles['HeaderMeta']
        )
        
        header_table = Table([[logo_cell, right_p]], colWidths=[300, 230])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (1,0), (1,0), 'RIGHT'),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 0),
            ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor('#CBD5E1')),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 12))
        
        # 1. Calcul des statistiques & KPIs
        total_devices = len(data)
        up_devices = sum(1 for item in data if item.get("status") == "UP")
        down_devices = total_devices - up_devices
        sla_pct = (up_devices / total_devices) * 100 if total_devices > 0 else 0.0
        
        latencies = [item.get("latency", 0) for item in data if item.get("status") == "UP"]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        
        # Cartes KPI
        kpi_data = [
            [
                Paragraph("<b>DISPONIBILITÉ (SLA)</b>", self.styles['KPITitle']),
                "",
                Paragraph("<b>ÉQUIPEMENTS SUIVIS</b>", self.styles['KPITitle']),
                "",
                Paragraph("<b>LATENCE MOYENNE (UP)</b>", self.styles['KPITitle'])
            ],
            [
                Paragraph(f"<font color='#10B981'><b>{sla_pct:.1f}%</b></font>", self.styles['KPIValue']),
                "",
                Paragraph(f"<font color='#6366F1'><b>{up_devices}</b></font> <font size='8' color='#64748B'>UP</font> <font color='#64748B'>/</font> <font color='#EF4444'><b>{down_devices}</b></font> <font size='8' color='#64748B'>DOWN</font>", self.styles['KPIValue']),
                "",
                Paragraph(f"<font color='#F59E0B'><b>{avg_latency:.1f}</b></font> <font size='8' color='#64748B'>ms</font>", self.styles['KPIValue'])
            ]
        ]
        
        kpi_table = Table(kpi_data, colWidths=[166, 16, 166, 16, 166])
        kpi_table.setStyle(TableStyle([
            # Style Card 1
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (0,-1), 1, colors.HexColor('#E2E8F0')),
            ('LINEBELOW', (0,0), (0,0), 0.5, colors.HexColor('#E2E8F0')),
            
            # Style Card 2
            ('BACKGROUND', (2,0), (2,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (2,0), (2,-1), 1, colors.HexColor('#E2E8F0')),
            ('LINEBELOW', (2,0), (2,0), 0.5, colors.HexColor('#E2E8F0')),
            
            # Style Card 3
            ('BACKGROUND', (4,0), (4,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (4,0), (4,-1), 1, colors.HexColor('#E2E8F0')),
            ('LINEBELOW', (4,0), (4,0), 0.5, colors.HexColor('#E2E8F0')),
            
            # Common alignments
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        elements.append(kpi_table)
        elements.append(Spacer(1, 12))
        
        # 2. Graphique comparatif des latences par équipement (Bar Chart)
        num_devices = len(data)
        if num_devices >= 1:
            elements.append(Paragraph("<b>COMPARAISON DES LATENCES PAR ÉQUIPEMENT (ms)</b>", self.styles['SectionHeader']))
            
            # calcul dynamique de la hauteur en fonction du nombre d'appareils
            plot_height = min(110, num_devices * 14)
            chart_height = plot_height + 25
            drawing = Drawing(530, chart_height)
            
            # background
            drawing.add(Rect(0, 0, 530, chart_height, fillColor=colors.HexColor('#F8FAFC'), strokeColor=colors.HexColor('#E2E8F0'), strokeWidth=1, rx=5, ry=5))
            
            left_margin = 120
            right_margin = 35
            plot_width = 530 - left_margin - right_margin
            bottom_margin = 18
            
            # trouver la latence max pour l'échelle
            max_lat = max(item.get("latency", 0) for item in data) if data else 10
            if max_lat <= 0:
                max_lat = 10
            if max_lat <= 10:
                x_max = 10
            elif max_lat <= 50:
                x_max = 50
            elif max_lat <= 100:
                x_max = 100
            elif max_lat <= 500:
                x_max = 500
            else:
                x_max = (int(max_lat / 100) + 1) * 100
                
            # Tracé des lignes de grille verticales
            for ratio in [0, 0.25, 0.5, 0.75, 1.0]:
                x = left_margin + ratio * plot_width
                val = ratio * x_max
                drawing.add(Line(x, bottom_margin, x, bottom_margin + plot_height, strokeColor=colors.HexColor('#E2E8F0'), strokeWidth=0.5))
                drawing.add(DString(x, bottom_margin - 10, f"{val:.0f}", fontName="Helvetica", fontSize=7, textAnchor="middle", fillColor=colors.HexColor('#64748B')))
                
            # Tracé des barres
            for i, item in enumerate(data):
                idx = num_devices - 1 - i
                y = bottom_margin + (idx / num_devices) * plot_height if num_devices > 1 else bottom_margin + plot_height / 2 - 5
                
                label = item.get("label", "Unknown")
                status = item.get("status", "DOWN")
                lat = item.get("latency", 0)
                
                if len(label) > 20:
                    label = label[:17] + "..."
                    
                # Libellé équipement
                drawing.add(DString(left_margin - 8, y + 1.5, label, fontName="Helvetica-Bold" if status == "UP" else "Helvetica", fontSize=7.5, textAnchor="end", fillColor=colors.HexColor('#1E293B')))
                
                # Barre
                if status == "UP":
                    bar_w = (lat / x_max) * plot_width
                    bar_color = colors.HexColor('#6366F1') if lat < 30 else (colors.HexColor('#F59E0B') if lat < 80 else colors.HexColor('#EF4444'))
                    drawing.add(Rect(left_margin, y, bar_w, 7, fillColor=bar_color, strokeColor=None))
                    drawing.add(DString(left_margin + bar_w + 3, y + 1.5, f"{lat:.0f} ms", fontName="Helvetica", fontSize=7, fillColor=colors.HexColor('#64748B')))
                else:
                    drawing.add(DString(left_margin + 5, y + 1.5, "HORS LIGNE (DOWN)", fontName="Helvetica-Bold", fontSize=7, fillColor=colors.HexColor('#EF4444')))
                    
            elements.append(drawing)
            elements.append(Spacer(1, 10))

        # 3. Tableau des équipements
        elements.append(Paragraph("<b>ÉTAT DÉTAILLÉ DES ÉQUIPEMENTS</b>", self.styles['SectionHeader']))
        
        table_data = [[
            Paragraph("<b>Équipement</b>", self.styles['TableHeader']),
            Paragraph("<b>IP / Hôte</b>", self.styles['TableHeader']),
            Paragraph("<b>Statut</b>", self.styles['TableHeader']),
            Paragraph("<b>Temps de réponse</b>", self.styles['TableHeader']),
            Paragraph("<b>Disponibilité</b>", self.styles['TableHeader'])
        ]]
        
        for item in data:
            status = item.get("status", "N/A")
            latency = item.get("latency", 0)
            avail = item.get("availability", 100.0)
            
            if status == "UP":
                status_cell = "<font color='#10B981'><b>● EN LIGNE (UP)</b></font>"
                latency_color = '#10B981' if latency < 25 else ('#F59E0B' if latency < 80 else '#EF4444')
                latency_cell = f"<font color='{latency_color}'><b>{latency} ms</b></font>"
            else:
                status_cell = "<font color='#EF4444'><b>● INACTIF (DOWN)</b></font>"
                latency_cell = "<font color='#64748B'>—</font>"
                
            avail_color = '#10B981' if avail >= 99.0 else ('#F59E0B' if avail >= 95.0 else '#EF4444')
            avail_cell = f"<font color='{avail_color}'><b>{avail:.1f}%</b></font>"
                
            table_data.append([
                Paragraph(item.get("label", "Unknown"), self.styles['TableText']),
                Paragraph(item.get("ip", "Unknown"), self.styles['TableTextCenter']),
                Paragraph(status_cell, self.styles['TableTextCenter']),
                Paragraph(latency_cell, self.styles['TableTextCenter']),
                Paragraph(avail_cell, self.styles['TableTextCenter'])
            ])
            
        table = Table(table_data, colWidths=[130, 110, 100, 100, 90])
        
        style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,0), 6),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ])
        
        for r in range(1, len(table_data)):
            bg_color = colors.HexColor('#FFFFFF') if r % 2 == 1 else colors.HexColor('#F8FAFC')
            style.add('BACKGROUND', (0, r), (-1, r), bg_color)
            style.add('TOPPADDING', (0, r), (-1, r), 5)
            style.add('BOTTOMPADDING', (0, r), (-1, r), 5)
            
        table.setStyle(style)
        elements.append(table)
        
        # 4. Journal d'événements (Event Log)
        if event_log_text:
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("<b>JOURNAL D'ÉVÉNEMENTS (LOG SURVEILLANCE)</b>", self.styles['SectionHeader']))
            
            log_rows = []
            log_lines = event_log_text.split('\n')
            for line in log_lines:
                line = line.strip()
                if not line:
                    continue
                    
                if "[ERROR]" in line:
                    line_formatted = f"<font color='#EF4444'><b>[CRITIQUE]</b></font> <font color='#EF4444'>{line}</font>"
                elif "[WARNING]" in line or "[WARN]" in line:
                    line_formatted = f"<font color='#F59E0B'><b>[ALERTE]</b></font> <font color='#D97706'>{line}</font>"
                elif "[INFO]" in line:
                    if "-> UP" in line or "ONLINE" in line:
                        line_formatted = f"<font color='#10B981'><b>[INFO]</b></font> <font color='#10B981'>{line}</font>"
                    else:
                        line_formatted = f"<font color='#10B981'><b>[INFO]</b></font> <font color='#475569'>{line}</font>"
                else:
                    # Fallback si aucun tag de crochet n'est trouvé
                    if "ERROR" in line or "FAIL" in line:
                        line_formatted = f"<font color='#EF4444'><b>[CRITIQUE]</b></font> <font color='#EF4444'>{line}</font>"
                    elif "WARNING" in line:
                        line_formatted = f"<font color='#F59E0B'><b>[ALERTE]</b></font> <font color='#D97706'>{line}</font>"
                    elif "-> UP" in line or "UP" in line:
                        line_formatted = f"<font color='#10B981'><b>[INFO]</b></font> <font color='#10B981'>{line}</font>"
                    else:
                        line_formatted = f"<font color='#64748B'><b>[INFO]</b></font> {line}"
                    
                log_rows.append([Paragraph(line_formatted, self.styles['LogLine'])])
                
            if log_rows:
                log_table = Table(log_rows, colWidths=[530])
                log_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
                    ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
                    ('TOPPADDING', (0,0), (-1,-1), 3),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                    ('LEFTPADDING', (0,0), (-1,-1), 8),
                    ('RIGHTPADDING', (0,0), (-1,-1), 8),
                ]))
                elements.append(log_table)
        
        # Pied de page dynamique
        def add_footer(canvas, doc):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor('#CBD5E1'))
            canvas.setLineWidth(0.5)
            canvas.line(36, 40, doc.pagesize[0] - 36, 40)
            
            canvas.setFont('Helvetica', 8)
            canvas.setFillColor(colors.HexColor('#64748B'))
            canvas.drawString(36, 25, "BahaaIT Network Tools — Rapport de Surveillance")
            
            page_num = canvas.getPageNumber()
            canvas.drawRightString(doc.pagesize[0] - 36, 25, f"Page {page_num}")
            canvas.restoreState()
            
        # Construction du document PDF
        try:
            doc.build(elements, onFirstPage=add_footer, onLaterPages=add_footer)
            return True, save_path
        except Exception as e:
            return False, str(e)

    def generate_speedtest_report(self, data, save_path=None):
        if not data:
            return False, "Aucune donnée disponible pour le rapport."

        if not save_path:
            save_path = os.path.join(os.path.expanduser("~"), "Desktop", "BahaaIT_Speedtest_Report.pdf")
            
        # Obtenir l'IP publique
        import requests
        try:
            public_ip = requests.get('https://api.ipify.org', timeout=3).text.strip()
        except:
            public_ip = "Non détectée"
            
        # Imports requises pour le tracé graphique de tendance
        from reportlab.graphics.shapes import Drawing, Rect, String as DString, Line, Circle, PolyLine
        import sys
        
        # Configuration du document
        doc = SimpleDocTemplate(
            save_path,
            pagesize=letter,
            title="BahaaIT Speedtest Report",
            author="BahaaIT Network Tools",
            creator="BahaaIT Network Tools",
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=54
        )
        elements = []
        
        # Logo & Header
        if getattr(sys, 'frozen', False):
            logo_path = os.path.join(sys._MEIPASS, "src", "assets", "logo.png")
        else:
            logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png"))
            
        # Header Layout
        logo_cell = ""
        if os.path.exists(logo_path):
            logo_img = Image(logo_path, width=32, height=32)
            logo_img.hAlign = 'LEFT'
            
            title_p = Paragraph("<font size='15' color='#1E293B'><b>BahaaIT Network Tools</b></font>", self.styles['HeaderAppTitle'])
            logo_cell = Table([[logo_img, title_p]], colWidths=[40, 260])
            logo_cell.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('LEFTPADDING', (0,0), (-1,-1), 0),
                ('RIGHTPADDING', (0,0), (-1,-1), 0),
                ('TOPPADDING', (0,0), (-1,-1), 0),
                ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ]))
        else:
            logo_cell = Paragraph("<font size='15' color='#1E293B'><b>BahaaIT Network Tools</b></font>", self.styles['HeaderAppTitle'])
            
        right_p = Paragraph(
            f"<font size='11' color='#6366F1'><b>Rapport de Performance Vitesse</b></font><br/>"
            f"<font size='8' color='#64748B'>Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</font>",
            self.styles['HeaderMeta']
        )
        
        header_table = Table([[logo_cell, right_p]], colWidths=[300, 230])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (1,0), (1,0), 'RIGHT'),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 0),
            ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor('#CBD5E1')),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 12))
        
        # 1. Calcul des statistiques & KPIs
        downloads = [item.get("download", 0) for item in data]
        uploads = [item.get("upload", 0) for item in data]
        pings = [item.get("ping", 0) for item in data]
        jitters = [item.get("jitter", 0) or 0 for item in data]
        losses = [item.get("packet_loss", 0) or 0 for item in data]
        
        avg_download = sum(downloads) / len(downloads) if downloads else 0
        avg_upload = sum(uploads) / len(uploads) if uploads else 0
        avg_ping = sum(pings) / len(pings) if pings else 0
        avg_jitter = sum(jitters) / len(jitters) if jitters else 0
        avg_loss = sum(losses) / len(losses) if losses else 0
        
        # Cartes KPI
        kpi_data = [
            [
                Paragraph("<b>TÉLÉCHARGEMENT MOYEN</b>", self.styles['KPITitle']),
                "",
                Paragraph("<b>ENVOI MOYEN</b>", self.styles['KPITitle']),
                "",
                Paragraph("<b>LATENCE MOYENNE (PING)</b>", self.styles['KPITitle'])
            ],
            [
                Paragraph(f"<font color='#6366F1'><b>{avg_download:.2f}</b></font> <font size='8' color='#64748B'>Mbps</font>", self.styles['KPIValue']),
                "",
                Paragraph(f"<font color='#F59E0B'><b>{avg_upload:.2f}</b></font> <font size='8' color='#64748B'>Mbps</font>", self.styles['KPIValue']),
                "",
                Paragraph(f"<font color='#10B981'><b>{avg_ping:.1f}</b></font> <font size='8' color='#64748B'>ms</font>", self.styles['KPIValue'])
            ]
        ]
        
        kpi_table = Table(kpi_data, colWidths=[166, 16, 166, 16, 166])
        kpi_table.setStyle(TableStyle([
            # Style Card 1
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (0,-1), 1, colors.HexColor('#E2E8F0')),
            ('LINEBELOW', (0,0), (0,0), 0.5, colors.HexColor('#E2E8F0')),
            
            # Style Card 2
            ('BACKGROUND', (2,0), (2,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (2,0), (2,-1), 1, colors.HexColor('#E2E8F0')),
            ('LINEBELOW', (2,0), (2,0), 0.5, colors.HexColor('#E2E8F0')),
            
            # Style Card 3
            ('BACKGROUND', (4,0), (4,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (4,0), (4,-1), 1, colors.HexColor('#E2E8F0')),
            ('LINEBELOW', (4,0), (4,0), 0.5, colors.HexColor('#E2E8F0')),
            
            # Common alignments
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        elements.append(kpi_table)
        elements.append(Spacer(1, 12))
        
        # 2. Graphique de tendance (Derniers 10 tests dans l'ordre chronologique)
        chart_data = list(reversed(data[:10]))
        num_points = len(chart_data)
        
        if num_points >= 1:
            elements.append(Paragraph("<b>ÉVOLUTION DES DÉBITS (10 DERNIERS TESTS)</b>", self.styles['SectionHeader']))
            drawing = Drawing(530, 130)
            
            # Background
            drawing.add(Rect(0, 0, 530, 130, fillColor=colors.HexColor('#F8FAFC'), strokeColor=colors.HexColor('#E2E8F0'), strokeWidth=1, rx=5, ry=5))
            
            plot_height = 85
            plot_width = 460
            left_margin = 45
            bottom_margin = 25
            
            # Détermination de l'échelle max (Y)
            max_speed = max(max(downloads) if downloads else 100, max(uploads) if uploads else 50)
            if max_speed <= 10:
                y_max = 10
            elif max_speed <= 50:
                y_max = 50
            elif max_speed <= 100:
                y_max = 100
            elif max_speed <= 500:
                y_max = 500
            else:
                y_max = (int(max_speed / 100) + 1) * 100
                
            # Tracé des lignes de grille horizontales et des libellés Y
            for ratio in [0, 0.25, 0.5, 0.75, 1.0]:
                y = bottom_margin + ratio * plot_height
                val = ratio * y_max
                drawing.add(Line(left_margin, y, left_margin + plot_width, y, strokeColor=colors.HexColor('#E2E8F0'), strokeWidth=0.5))
                drawing.add(DString(left_margin - 8, y - 3, f"{val:.0f}", fontName="Helvetica", fontSize=7, textAnchor="end", fillColor=colors.HexColor('#64748B')))
                
            # Tracé de l'axe des temps (X)
            for i, item in enumerate(chart_data):
                x = left_margin + (i / (num_points - 1) * plot_width) if num_points > 1 else left_margin + plot_width / 2
                ts = item.get("timestamp", "")
                try:
                    dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    short_ts = dt.strftime("%d/%m %H:%M")
                except:
                    short_ts = ts[-8:]
                    
                # Éviter la surcharge des labels
                if num_points <= 5 or i % (num_points // 4 + 1) == 0 or i == num_points - 1:
                    drawing.add(DString(x, bottom_margin - 12, short_ts, fontName="Helvetica", fontSize=7, textAnchor="middle", fillColor=colors.HexColor('#64748B')))
                    drawing.add(Line(x, bottom_margin, x, bottom_margin - 3, strokeColor=colors.HexColor('#CBD5E1'), strokeWidth=0.5))
            
            # Tracé des points et lignes
            dl_coords = []
            ul_coords = []
            for i, item in enumerate(chart_data):
                x = left_margin + (i / (num_points - 1) * plot_width) if num_points > 1 else left_margin + plot_width / 2
                dl_val = item.get("download", 0)
                ul_val = item.get("upload", 0)
                
                y_dl = bottom_margin + (dl_val / y_max) * plot_height
                y_ul = bottom_margin + (ul_val / y_max) * plot_height
                
                dl_coords.extend([x, y_dl])
                ul_coords.extend([x, y_ul])
                
                # Cercles pour chaque point
                drawing.add(Circle(x, y_dl, 2.5, fillColor=colors.HexColor('#6366F1'), strokeColor=colors.white, strokeWidth=0.8))
                drawing.add(Circle(x, y_ul, 2.5, fillColor=colors.HexColor('#F59E0B'), strokeColor=colors.white, strokeWidth=0.8))
                
            if num_points > 1:
                drawing.add(PolyLine(dl_coords, strokeColor=colors.HexColor('#6366F1'), strokeWidth=1.5))
                drawing.add(PolyLine(ul_coords, strokeColor=colors.HexColor('#F59E0B'), strokeWidth=1.5))
                
            # Légende
            # Téléchargement
            drawing.add(Rect(left_margin + 10, 115, 8, 5, fillColor=colors.HexColor('#6366F1'), strokeColor=None))
            drawing.add(DString(left_margin + 23, 114, "Téléchargement (Mbps)", fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor('#334155')))
            # Envoi
            drawing.add(Rect(left_margin + 140, 115, 8, 5, fillColor=colors.HexColor('#F59E0B'), strokeColor=None))
            drawing.add(DString(left_margin + 153, 114, "Envoi (Mbps)", fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor('#334155')))
            
            elements.append(drawing)
            elements.append(Spacer(1, 10))

        # 3. Diagnostic des usages (SLA) & Métadonnées système
        # Navigation Web
        if avg_download >= 15 and avg_ping <= 50:
            nav_status = "<font color='#10B981'><b>Excellent</b></font>"
            nav_desc = "Navigation ultra-fluide."
        elif avg_download >= 5 and avg_ping <= 120:
            nav_status = "<font color='#F59E0B'><b>Compatible</b></font>"
            nav_desc = "Navigation fluide pour les sites standards."
        else:
            nav_status = "<font color='#EF4444'><b>Limité</b></font>"
            nav_desc = "Chargement lent des pages web."
            
        # Visioconférence
        if avg_download >= 15 and avg_upload >= 5 and avg_ping <= 50 and avg_jitter <= 15 and avg_loss <= 0.5:
            video_status = "<font color='#10B981'><b>Excellent</b></font>"
            video_desc = "Appels HD fluides, sans latence."
        elif avg_download >= 5 and avg_upload >= 2 and avg_ping <= 90 and avg_jitter <= 25 and avg_loss <= 1.5:
            video_status = "<font color='#F59E0B'><b>Compatible</b></font>"
            video_desc = "Appels possibles en qualité standard."
        else:
            video_status = "<font color='#EF4444'><b>Non Recommandé</b></font>"
            video_desc = "Risque de saccades et déconnexions."
            
        # Streaming 4K
        if avg_download >= 25:
            stream_status = "<font color='#10B981'><b>Optimal (4K)</b></font>"
            stream_desc = "Idéal pour l'Ultra HD multi-écrans."
        elif avg_download >= 10:
            stream_status = "<font color='#F59E0B'><b>Compatible HD</b></font>"
            stream_desc = "Lecture fluide en Haute Définition."
        else:
            stream_status = "<font color='#EF4444'><b>Non Recommandé</b></font>"
            stream_desc = "Temps de chargement longs."
            
        # Gaming en ligne
        if avg_ping <= 30 and avg_jitter <= 10 and avg_loss == 0.0:
            gaming_status = "<font color='#10B981'><b>Optimal</b></font>"
            gaming_desc = "Temps de réponse minimal (idéal e-sport)."
        elif avg_ping <= 60 and avg_jitter <= 20 and avg_loss <= 1.0:
            gaming_status = "<font color='#F59E0B'><b>Compatible</b></font>"
            gaming_desc = "Expérience de jeu en ligne correcte."
        else:
            gaming_status = "<font color='#EF4444'><b>Instable</b></font>"
            gaming_desc = "Latence élevée (lag) et micro-coupures."

        elements.append(Paragraph("<b>DIAGNOSTIC D'ÉLIGIBILITÉ AUX USAGES</b>", self.styles['SectionHeader']))
        
        diag_data = [
            [Paragraph("<b>Activité</b>", self.styles['TableHeader']), Paragraph("<b>Statut</b>", self.styles['TableHeader']), Paragraph("<b>Observation</b>", self.styles['TableHeader'])],
            [Paragraph("<b>Navigation Web</b>", self.styles['TableText']), Paragraph(nav_status, self.styles['TableText']), Paragraph(nav_desc, self.styles['TableText'])],
            [Paragraph("<b>Visioconférence</b>", self.styles['TableText']), Paragraph(video_status, self.styles['TableText']), Paragraph(video_desc, self.styles['TableText'])],
            [Paragraph("<b>Streaming 4K</b>", self.styles['TableText']), Paragraph(stream_status, self.styles['TableText']), Paragraph(stream_desc, self.styles['TableText'])],
            [Paragraph("<b>Jeu en Ligne</b>", self.styles['TableText']), Paragraph(gaming_status, self.styles['TableText']), Paragraph(gaming_desc, self.styles['TableText'])],
        ]
        diag_table = Table(diag_data, colWidths=[90, 75, 115])
        diag_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#F8FAFC')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ]))
        
        meta_data = [
            [Paragraph("<b>INFORMATIONS SYSTÈME</b>", self.styles['MetaTitle'])],
            [Paragraph(f"<b>Opérateur détecté (ISP) :</b> {data[0].get('isp', 'Inconnu')}", self.styles['MetaText'])],
            [Paragraph(f"<b>Serveur de test :</b> {data[0].get('server', 'Inconnu')}", self.styles['MetaText'])],
            [Paragraph(f"<b>Historique analysé :</b> {len(data)} derniers tests", self.styles['MetaText'])],
            [Spacer(1, 4)],
            [Paragraph("<b>Adresse IP publique :</b>", self.styles['MetaTitle'])],
            [Paragraph(public_ip, self.styles['MetaText'])]
        ]
        meta_table = Table(meta_data, colWidths=[230])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        
        side_by_side = Table([[diag_table, "", meta_table]], colWidths=[280, 20, 230])
        side_by_side.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 0),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ('TOPPADDING', (0,0), (-1,-1), 0),
        ]))
        elements.append(side_by_side)
        elements.append(Spacer(1, 10))

        # 4. Tableau historique complet de données (avec couleurs conditionnelles)
        elements.append(Paragraph("<b>HISTORIQUE DÉTAILLÉ DES MESURES</b>", self.styles['SectionHeader']))
        
        table_data = [[
            Paragraph("<b>Date / Heure</b>", self.styles['TableHeader']),
            Paragraph("<b>Descendant (Mbps)</b>", self.styles['TableHeader']),
            Paragraph("<b>Montant (Mbps)</b>", self.styles['TableHeader']),
            Paragraph("<b>Ping (ms)</b>", self.styles['TableHeader']),
            Paragraph("<b>Jitter (ms)</b>", self.styles['TableHeader']),
            Paragraph("<b>Perte (%)</b>", self.styles['TableHeader'])
        ]]
        
        # Limiter à 25 entrées pour garder le rapport concis (2 pages max)
        for item in data[:25]:
            dl = item.get('download', 0)
            ul = item.get('upload', 0)
            ping = item.get('ping', 0)
            jitter = item.get('jitter', 0) or 0
            loss = item.get('packet_loss', 0) or 0
            
            # Coloration conditionnelle basée sur la qualité de la mesure
            dl_color = '#10B981' if dl >= 50 else ('#F59E0B' if dl >= 15 else '#EF4444')
            ul_color = '#10B981' if ul >= 15 else ('#F59E0B' if ul >= 5 else '#EF4444')
            ping_color = '#10B981' if ping <= 30 else ('#F59E0B' if ping <= 80 else '#EF4444')
            jitter_color = '#10B981' if jitter <= 10 else ('#F59E0B' if jitter <= 25 else '#EF4444')
            loss_color = '#10B981' if loss == 0 else ('#F59E0B' if loss <= 1.5 else '#EF4444')
            
            table_data.append([
                Paragraph(item.get("timestamp", "N/A"), self.styles['TableText']),
                Paragraph(f"<font color='{dl_color}'><b>{dl:.2f}</b></font>", self.styles['TableTextCenter']),
                Paragraph(f"<font color='{ul_color}'><b>{ul:.2f}</b></font>", self.styles['TableTextCenter']),
                Paragraph(f"<font color='{ping_color}'>{ping:.1f}</font>", self.styles['TableTextCenter']),
                Paragraph(f"<font color='{jitter_color}'>{jitter:.1f}</font>", self.styles['TableTextCenter']),
                Paragraph(f"<font color='{loss_color}'>{loss:.1f}%</font>", self.styles['TableTextCenter'])
            ])
            
        data_table = Table(table_data, colWidths=[120, 90, 90, 75, 75, 80])
        
        style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,0), 6),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ])
        
        # Lignes alternées
        for r in range(1, len(table_data)):
            bg_color = colors.HexColor('#FFFFFF') if r % 2 == 1 else colors.HexColor('#F8FAFC')
            style.add('BACKGROUND', (0, r), (-1, r), bg_color)
            style.add('TOPPADDING', (0, r), (-1, r), 4)
            style.add('BOTTOMPADDING', (0, r), (-1, r), 4)
            
        data_table.setStyle(style)
        elements.append(data_table)
        
        # Fonction de pied de page dynamique
        def add_footer(canvas, doc):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor('#CBD5E1'))
            canvas.setLineWidth(0.5)
            canvas.line(36, 40, doc.pagesize[0] - 36, 40)
            
            canvas.setFont('Helvetica', 8)
            canvas.setFillColor(colors.HexColor('#64748B'))
            canvas.drawString(36, 25, "BahaaIT Network Tools — Rapport de Performance")
            
            page_num = canvas.getPageNumber()
            canvas.drawRightString(doc.pagesize[0] - 36, 25, f"Page {page_num}")
            canvas.restoreState()
            
        # Construction du document PDF
        try:
            doc.build(elements, onFirstPage=add_footer, onLaterPages=add_footer)
            return True, save_path
        except Exception as e:
            return False, str(e)

    def generate_incidents_report(self, incidents, save_path=None):
        """Generate an Incident History PDF matching the Speedtest & Network Monitoring corporate template."""
        import html
        import sys
        from reportlab.graphics.shapes import Drawing, Line, Rect, String as DString

        if not save_path:
            save_path = os.path.join(os.path.expanduser("~"), "Desktop", "BahaaIT_Incidents_Report.pdf")

        incidents = list(incidents or [])

        doc = SimpleDocTemplate(
            save_path,
            pagesize=letter,
            title="BahaaIT Incident History Report",
            author="BahaaIT Network Tools",
            creator="BahaaIT Network Tools",
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=54,
        )
        elements = []

        # Logo & Header (identical layout to generate_speedtest_report)
        if getattr(sys, "frozen", False):
            logo_path = os.path.join(sys._MEIPASS, "src", "assets", "logo.png")
        else:
            logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png"))

        if os.path.exists(logo_path):
            logo_img = Image(logo_path, width=32, height=32)
            logo_img.hAlign = "LEFT"
            title_p = Paragraph("<font size='15' color='#1E293B'><b>BahaaIT Network Tools</b></font>", self.styles["HeaderAppTitle"])
            logo_cell = Table([[logo_img, title_p]], colWidths=[40, 260])
            logo_cell.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]))
        else:
            logo_cell = Paragraph("<font size='15' color='#1E293B'><b>BahaaIT Network Tools</b></font>", self.styles["HeaderAppTitle"])

        right_p = Paragraph(
            f"<font size='11' color='#6366F1'><b>Rapport d'Historique des Incidents</b></font><br/>"
            f"<font size='8' color='#64748B'>Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</font>",
            self.styles["HeaderMeta"],
        )

        header_table = Table([[logo_cell, right_p]], colWidths=[300, 230])
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("LINEBELOW", (0, 0), (-1, 0), 1, colors.HexColor("#CBD5E1")),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 12))

        # 1. KPI Summary Cards
        total = len(incidents)
        crit_cnt = sum(1 for i in incidents if str(i.get("severity", "")).upper() == "CRITICAL")
        warn_cnt = sum(1 for i in incidents if str(i.get("severity", "")).upper() == "WARNING")
        info_cnt = max(0, total - crit_cnt - warn_cnt)
        active_cnt = sum(1 for i in incidents if str(i.get("status", "")).upper() in ("DETECTED", "ACKNOWLEDGED"))
        resolved_cnt = total - active_cnt
        avg_dur_s = (sum(float(i.get("duration_seconds", 0.0) or 0.0) for i in incidents) / total) if total else 0.0
        avg_loss = (sum(float(i.get("packet_loss_pct", 0.0) or 0.0) for i in incidents) / total) if total else 0.0

        def _fmt_dur(sec: float) -> str:
            s = int(max(0, round(sec)))
            if s < 60:
                return f"{s}s"
            if s < 3600:
                return f"{s // 60}m {s % 60}s"
            return f"{s // 3600}h {(s % 3600) // 60}m"

        kpi_data = [
            [
                Paragraph("<b>TOTAL INCIDENTS</b>", self.styles["KPITitle"]),
                "",
                Paragraph("<b>ÉTAT DES INCIDENTS</b>", self.styles["KPITitle"]),
                "",
                Paragraph("<b>DURÉE &amp; PERTE MOY.</b>", self.styles["KPITitle"]),
            ],
            [
                Paragraph(
                    f"<font color='#6366F1'><b>{total}</b></font> "
                    f"<font size='8' color='#64748B'>({crit_cnt} CRIT / {warn_cnt} WARN)</font>",
                    self.styles["KPIValue"],
                ),
                "",
                Paragraph(
                    f"<font color='#EF4444'><b>{active_cnt}</b></font> <font size='8' color='#64748B'>ACTIFS</font> "
                    f"<font color='#64748B'>/</font> "
                    f"<font color='#10B981'><b>{resolved_cnt}</b></font> <font size='8' color='#64748B'>RÉSOLUS</font>",
                    self.styles["KPIValue"],
                ),
                "",
                Paragraph(
                    f"<font color='#F59E0B'><b>{_fmt_dur(avg_dur_s)}</b></font> "
                    f"<font size='8' color='#64748B'>• {avg_loss:.1f}%</font>",
                    self.styles["KPIValue"],
                ),
            ],
        ]
        kpi_table = Table(kpi_data, colWidths=[166, 16, 166, 16, 166])
        kpi_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (0, -1), 1, colors.HexColor("#E2E8F0")),
            ("LINEBELOW", (0, 0), (0, 0), 0.5, colors.HexColor("#E2E8F0")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (2, 0), (2, -1), 1, colors.HexColor("#E2E8F0")),
            ("LINEBELOW", (2, 0), (2, 0), 0.5, colors.HexColor("#E2E8F0")),
            ("BACKGROUND", (4, 0), (4, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (4, 0), (4, -1), 1, colors.HexColor("#E2E8F0")),
            ("LINEBELOW", (4, 0), (4, 0), 0.5, colors.HexColor("#E2E8F0")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(kpi_table)
        elements.append(Spacer(1, 12))

        # 2. Distribution Chart (Severity & Status)
        elements.append(Paragraph("<b>RÉPARTITION PAR GRAVITÉ &amp; STATUT</b>", self.styles["SectionHeader"]))
        drawing = Drawing(530, 88)
        drawing.add(Rect(0, 0, 530, 88, fillColor=colors.HexColor("#F8FAFC"), strokeColor=colors.HexColor("#E2E8F0"), strokeWidth=1, rx=5, ry=5))
        bars = [
            ("Critique (CRITICAL)", crit_cnt, colors.HexColor("#EF4444")),
            ("Alerte (WARNING)", warn_cnt, colors.HexColor("#F59E0B")),
            ("Info (INFO)", info_cnt, colors.HexColor("#6366F1")),
            ("Actifs (DETECTED/ACK)", active_cnt, colors.HexColor("#10B981") if active_cnt == 0 else colors.HexColor("#EF4444")),
        ]
        max_cnt = max([b[1] for b in bars] + [1])
        left_m = 135
        bar_max_w = 340
        for idx, (lbl, cnt, col) in enumerate(bars):
            y = 66 - idx * 17
            drawing.add(DString(left_m - 8, y + 1.5, lbl, fontName="Helvetica-Bold", fontSize=7.5, textAnchor="end", fillColor=colors.HexColor("#1E293B")))
            drawing.add(Rect(left_m, y, bar_max_w, 8, fillColor=colors.HexColor("#E2E8F0"), strokeColor=None, rx=2, ry=2))
            if cnt > 0:
                w = max(4.0, (cnt / max_cnt) * bar_max_w)
                drawing.add(Rect(left_m, y, w, 8, fillColor=col, strokeColor=None, rx=2, ry=2))
            drawing.add(DString(left_m + bar_max_w + 8, y + 1.5, str(cnt), fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#334155")))
        elements.append(drawing)
        elements.append(Spacer(1, 12))

        # 3. Detailed Incidents Table
        elements.append(Paragraph("<b>HISTORIQUE DÉTAILLÉ DES INCIDENTS</b>", self.styles["SectionHeader"]))
        if not incidents:
            elements.append(Paragraph("Aucun incident enregistré sur la période sélectionnée.", self.styles["MetaText"]))
        else:
            table_data = [[
                Paragraph("<b>Incident / Début</b>", self.styles["TableHeader"]),
                Paragraph("<b>Équipement &amp; Type</b>", self.styles["TableHeader"]),
                Paragraph("<b>Gravité</b>", self.styles["TableHeader"]),
                Paragraph("<b>Statut</b>", self.styles["TableHeader"]),
                Paragraph("<b>Durée</b>", self.styles["TableHeader"]),
                Paragraph("<b>Perte</b>", self.styles["TableHeader"]),
                Paragraph("<b>Diagnostic &amp; Commentaires</b>", self.styles["TableHeader"]),
            ]]

            for inc in incidents:
                uid = html.escape(str(inc.get("incident_uid", "")), quote=False)
                start_raw = inc.get("start_time")
                start_s = start_raw.strftime("%Y-%m-%d %H:%M") if isinstance(start_raw, datetime) else html.escape(str(start_raw or ""), quote=False)
                h_name = html.escape(str(inc.get("host_name", "")), quote=False)
                h_addr = html.escape(str(inc.get("host_address", "")), quote=False)
                inc_type = html.escape(str(inc.get("incident_type", "")), quote=False)
                sev = str(inc.get("severity", "INFO")).upper()
                st = str(inc.get("status", "DETECTED")).upper()
                dur_s = _fmt_dur(float(inc.get("duration_seconds", 0.0) or 0.0))
                loss = float(inc.get("packet_loss_pct", 0.0) or 0.0)
                pre_lat = float(inc.get("avg_latency_before_ms", 0.0) or 0.0)
                rec_lat = inc.get("recovery_latency_ms")
                comment_lines = [ln.strip() for ln in (inc.get("comments") or "").splitlines() if ln.strip()]

                sev_col = "#EF4444" if sev == "CRITICAL" else ("#F59E0B" if sev == "WARNING" else "#38BDF8")
                if st in ("DETECTED",):
                    st_col = "#EF4444"
                elif st == "ACKNOWLEDGED":
                    st_col = "#F59E0B"
                elif st == "RECOVERED":
                    st_col = "#10B981"
                else:
                    st_col = "#64748B"
                loss_col = "#EF4444" if loss >= 50 else ("#F59E0B" if loss > 0 else "#10B981")

                lat_info = f"Avant: {pre_lat:.0f}ms"
                if rec_lat is not None:
                    lat_info += f" | Reprise: {float(rec_lat):.0f}ms"

                detail_parts = [lat_info]
                if inc.get("acknowledged"):
                    ack_raw = inc.get("acknowledged_at")
                    ack_s = ack_raw.strftime("%Y-%m-%d %H:%M") if isinstance(ack_raw, datetime) else str(ack_raw or "")
                    ack_badge = "<font color='#0F766E'><b>Acquitté</b></font>"
                    if ack_s:
                        ack_badge += f" <font size='7' color='#0F766E'>({html.escape(ack_s, quote=False)})</font>"
                    detail_parts.append(ack_badge)

                if comment_lines:
                    inline_parts = []
                    remaining = 260
                    truncated_inline = False
                    for ln in comment_lines:
                        if remaining <= 0:
                            truncated_inline = True
                            break
                        if len(ln) <= remaining:
                            snippet = ln
                        else:
                            snippet = ln[:max(1, remaining - 3)].rstrip() + "..."
                            truncated_inline = True
                        remaining -= len(ln) + 1
                        esc_ln = html.escape(snippet, quote=False)
                        col_hex = "#312E81" if ln.startswith("[") else "#475569"
                        inline_parts.append(f"<font color='{col_hex}'>{esc_ln}</font>")
                    if truncated_inline:
                        inline_parts.append("<font size='7' color='#6366F1'><i>(voir détail complet ci-dessous)</i></font>")
                    detail_parts.extend(inline_parts)

                detail_cell = "<br/>".join(detail_parts)

                table_data.append([
                    Paragraph(f"<b>{uid}</b><br/><font size='7' color='#64748B'>{start_s}</font>", self.styles["TableText"]),
                    Paragraph(f"<b>{h_name}</b><br/><font color='#6366F1'>{h_addr}</font><br/><font size='7' color='#64748B'>{inc_type}</font>", self.styles["TableText"]),
                    Paragraph(f"<font color='{sev_col}'><b>{html.escape(sev, quote=False)}</b></font>", self.styles["TableTextCenter"]),
                    Paragraph(f"<font color='{st_col}'><b>{html.escape(st, quote=False)}</b></font>", self.styles["TableTextCenter"]),
                    Paragraph(dur_s, self.styles["TableTextCenter"]),
                    Paragraph(f"<font color='{loss_col}'><b>{loss:.1f}%</b></font>", self.styles["TableTextCenter"]),
                    Paragraph(detail_cell, self.styles["TableText"]),
                ])

            inc_table = Table(table_data, colWidths=[88, 92, 58, 66, 46, 46, 134], repeatRows=1)
            tbl_style = TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, 0), 6),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ])
            for r in range(1, len(table_data)):
                bg_color = colors.HexColor("#FFFFFF") if r % 2 == 1 else colors.HexColor("#F8FAFC")
                tbl_style.add("BACKGROUND", (0, r), (-1, r), bg_color)
                tbl_style.add("TOPPADDING", (0, r), (-1, r), 5)
                tbl_style.add("BOTTOMPADDING", (0, r), (-1, r), 5)
            inc_table.setStyle(tbl_style)
            elements.append(inc_table)

            # 4. Full Unabridged Technician Comments & Interventions Log
            commented_incidents = [
                i for i in incidents
                if (i.get("comments") or "").strip() or i.get("acknowledged")
            ]
            if commented_incidents:
                elements.append(Spacer(1, 12))
                elements.append(
                    Paragraph("<b>JOURNAL DES COMMENTAIRES &amp; INTERVENTIONS</b>", self.styles["SectionHeader"])
                )
                note_rows = []
                for inc in commented_incidents:
                    uid = html.escape(str(inc.get("incident_uid", "")), quote=False)
                    h_name = html.escape(str(inc.get("host_name", "")), quote=False)
                    h_addr = html.escape(str(inc.get("host_address", "")), quote=False)
                    st = str(inc.get("status", "DETECTED")).upper()
                    if st == "DETECTED":
                        st_col = "#EF4444"
                    elif st == "ACKNOWLEDGED":
                        st_col = "#F59E0B"
                    elif st == "RECOVERED":
                        st_col = "#10B981"
                    else:
                        st_col = "#64748B"

                    header_line = (
                        f"<b>{uid}</b> — {h_name} (<font color='#6366F1'>{h_addr}</font>) "
                        f"| <font color='{st_col}'><b>{html.escape(st, quote=False)}</b></font>"
                    )
                    if inc.get("acknowledged"):
                        ack_raw = inc.get("acknowledged_at")
                        ack_s = ack_raw.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ack_raw, datetime) else str(ack_raw or "")
                        if ack_s:
                            header_line += f" <font color='#0F766E'><b>• Acquitté le {html.escape(ack_s, quote=False)}</b></font>"
                        else:
                            header_line += " <font color='#0F766E'><b>• Acquitté</b></font>"

                    lines = [ln.strip() for ln in (inc.get("comments") or "").splitlines() if ln.strip()]
                    body_lines = []
                    for ln in lines:
                        esc_ln = html.escape(ln, quote=False)
                        col_hex = "#312E81" if ln.startswith("[") else "#475569"
                        body_lines.append(f"<font color='{col_hex}'>• {esc_ln}</font>")
                    if not body_lines:
                        body_lines.append("<font color='#64748B'><i>Incident acquitté sans note complémentaire.</i></font>")

                    cell_html = header_line + "<br/>" + "<br/>".join(body_lines)
                    note_rows.append([Paragraph(cell_html, self.styles["TableText"])])

                notes_table = Table(note_rows, colWidths=[530])
                notes_style_cmds = [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
                if len(note_rows) > 1:
                    notes_style_cmds.append(("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#E2E8F0")))
                notes_table.setStyle(TableStyle(notes_style_cmds))
                elements.append(notes_table)

        def add_footer(canvas, doc_obj):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
            canvas.setLineWidth(0.5)
            canvas.line(36, 40, doc_obj.pagesize[0] - 36, 40)
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#64748B"))
            canvas.drawString(36, 25, "BahaaIT Network Tools — Rapport d'Historique des Incidents")
            canvas.drawRightString(doc_obj.pagesize[0] - 36, 25, f"Page {canvas.getPageNumber()}")
            canvas.restoreState()

        try:
            doc.build(elements, onFirstPage=add_footer, onLaterPages=add_footer)
            return True, save_path
        except Exception as e:
            return False, str(e)

    def _build_corporate_header(self, subtitle_text: str) -> Table:
        """Build a shared WinAnsi-safe corporate ReportLab header table."""
        import html
        import sys

        if getattr(sys, "frozen", False):
            logo_path = os.path.join(sys._MEIPASS, "src", "assets", "logo.png")
        else:
            logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png"))

        if os.path.exists(logo_path):
            logo_img = Image(logo_path, width=32, height=32)
            logo_img.hAlign = "LEFT"
            title_p = Paragraph("<font size='15' color='#1E293B'><b>BahaaIT Network Tools</b></font>", self.styles["HeaderAppTitle"])
            logo_cell = Table([[logo_img, title_p]], colWidths=[40, 260])
            logo_cell.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]))
        else:
            logo_cell = Paragraph("<font size='15' color='#1E293B'><b>BahaaIT Network Tools</b></font>", self.styles["HeaderAppTitle"])

        safe_sub = html.escape(str(subtitle_text or ""), quote=False)
        right_p = Paragraph(
            f"<font size='11' color='#6366F1'><b>{safe_sub}</b></font><br/>"
            f"<font size='8' color='#64748B'>Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</font>",
            self.styles["HeaderMeta"],
        )
        header_table = Table([[logo_cell, right_p]], colWidths=[300, 230])
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("LINEBELOW", (0, 0), (-1, 0), 1, colors.HexColor("#CBD5E1")),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ]))
        return header_table

    def _build_device_inventory_table(self, devices: list) -> Table:
        """Build a shared device inventory table for both Global Inventory and Site PDF reports."""
        import html

        table_data = [[
            Paragraph("<b>Équipement / IP</b>", self.styles["TableHeader"]),
            Paragraph("<b>Catégorie / Site</b>", self.styles["TableHeader"]),
            Paragraph("<b>Constructeur / Modèle</b>", self.styles["TableHeader"]),
            Paragraph("<b>MAC / Série</b>", self.styles["TableHeader"]),
            Paragraph("<b>Firmware / Baie</b>", self.styles["TableHeader"]),
            Paragraph("<b>Statut</b>", self.styles["TableHeader"]),
        ]]

        for dev in devices:
            host = html.escape(str(dev.get("hostname", "")), quote=False)
            ip = html.escape(str(dev.get("management_ip", "")), quote=False)
            cat = html.escape(str(dev.get("category", "Other")), quote=False)
            site = html.escape(str(dev.get("site_name") or "—"), quote=False)
            vendor = html.escape(str(dev.get("vendor") or "Unknown"), quote=False)
            model = html.escape(str(dev.get("model") or "—"), quote=False)
            mac = html.escape(str(dev.get("mac_address") or "—"), quote=False)
            serial = html.escape(str(dev.get("serial_number") or "—"), quote=False)
            fw = html.escape(str(dev.get("firmware_version") or "—"), quote=False)
            rack = html.escape(str(dev.get("rack_location") or "—"), quote=False)
            st = str(dev.get("status") or "UNKNOWN").upper()

            if st in ("UP", "ONLINE", "OK"):
                st_col = "#10B981"
            elif st in ("DEGRADED", "WARNING", "RECOVERING"):
                st_col = "#F59E0B"
            elif st in ("DOWN", "OFFLINE", "CRITICAL"):
                st_col = "#EF4444"
            else:
                st_col = "#64748B"

            table_data.append([
                Paragraph(f"<b>{host}</b><br/><font color='#6366F1'>{ip}</font>", self.styles["TableText"]),
                Paragraph(f"<b>{cat}</b><br/><font size='7' color='#64748B'>{site}</font>", self.styles["TableText"]),
                Paragraph(f"{vendor}<br/><font size='7' color='#64748B'>{model}</font>", self.styles["TableText"]),
                Paragraph(f"{mac}<br/><font size='7' color='#64748B'>S/N: {serial}</font>", self.styles["TableText"]),
                Paragraph(f"{fw}<br/><font size='7' color='#64748B'>{rack}</font>", self.styles["TableText"]),
                Paragraph(f"<font color='{st_col}'><b>{html.escape(st, quote=False)}</b></font>", self.styles["TableTextCenter"]),
            ])

        tbl = Table(table_data, colWidths=[105, 92, 95, 98, 80, 60], repeatRows=1)
        style = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, 0), 6),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ])
        for r in range(1, len(table_data)):
            bg = colors.HexColor("#FFFFFF") if r % 2 == 1 else colors.HexColor("#F8FAFC")
            style.add("BACKGROUND", (0, r), (-1, r), bg)
            style.add("TOPPADDING", (0, r), (-1, r), 4)
            style.add("BOTTOMPADDING", (0, r), (-1, r), 4)
        tbl.setStyle(style)
        return tbl

    def generate_inventory_report(self, devices, save_path=None, title="Rapport d'Inventaire Infrastructure"):
        """Generate a corporate PDF report for the centralized infrastructure device inventory."""
        if not save_path:
            save_path = os.path.join(os.path.expanduser("~"), "Desktop", "BahaaIT_Inventory_Report.pdf")

        items = list(devices or [])
        doc = SimpleDocTemplate(
            save_path,
            pagesize=letter,
            title="BahaaIT Infrastructure Inventory Report",
            author="BahaaIT Network Tools",
            creator="BahaaIT Network Tools",
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=54,
        )
        elements = [self._build_corporate_header(title), Spacer(1, 12)]

        total = len(items)
        online = sum(1 for d in items if str(d.get("status", "")).upper() in ("UP", "ONLINE", "OK"))
        degraded = sum(1 for d in items if str(d.get("status", "")).upper() in ("DEGRADED", "WARNING", "RECOVERING"))
        offline = sum(1 for d in items if str(d.get("status", "")).upper() in ("DOWN", "OFFLINE", "CRITICAL"))
        sites_cnt = len({d.get("site_name") for d in items if d.get("site_name")})

        kpi_data = [
            [
                Paragraph("<b>TOTAL ÉQUIPEMENTS</b>", self.styles["KPITitle"]),
                "",
                Paragraph("<b>ÉTAT OPÉRATIONNEL</b>", self.styles["KPITitle"]),
                "",
                Paragraph("<b>SITES COUVERTS</b>", self.styles["KPITitle"]),
            ],
            [
                Paragraph(f"<font color='#6366F1'><b>{total}</b></font>", self.styles["KPIValue"]),
                "",
                Paragraph(
                    f"<font color='#10B981'><b>{online}</b></font> UP / "
                    f"<font color='#F59E0B'><b>{degraded}</b></font> DEG / "
                    f"<font color='#EF4444'><b>{offline}</b></font> OFF",
                    self.styles["TableTextCenter"],
                ),
                "",
                Paragraph(f"<font color='#06B6D4'><b>{sites_cnt}</b></font>", self.styles["KPIValue"]),
            ],
        ]
        kpi_tbl = Table(kpi_data, colWidths=[166, 16, 166, 16, 166])
        kpi_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (0, -1), 1, colors.HexColor("#E2E8F0")),
            ("LINEBELOW", (0, 0), (0, 0), 0.5, colors.HexColor("#E2E8F0")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (2, 0), (2, -1), 1, colors.HexColor("#E2E8F0")),
            ("LINEBELOW", (2, 0), (2, 0), 0.5, colors.HexColor("#E2E8F0")),
            ("BACKGROUND", (4, 0), (4, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (4, 0), (4, -1), 1, colors.HexColor("#E2E8F0")),
            ("LINEBELOW", (4, 0), (4, 0), 0.5, colors.HexColor("#E2E8F0")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(kpi_tbl)
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("<b>INVENTAIRE DÉTAILLÉ DES ÉQUIPEMENTS</b>", self.styles["SectionHeader"]))
        if items:
            elements.append(self._build_device_inventory_table(items))
        else:
            elements.append(Paragraph("Aucun équipement enregistré dans l'inventaire.", self.styles["MetaText"]))

        def add_footer(canvas, doc_obj):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
            canvas.setLineWidth(0.5)
            canvas.line(36, 40, doc_obj.pagesize[0] - 36, 40)
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#64748B"))
            canvas.drawString(36, 25, "BahaaIT Network Tools — Inventaire Infrastructure")
            canvas.drawRightString(doc_obj.pagesize[0] - 36, 25, f"Page {canvas.getPageNumber()}")
            canvas.restoreState()

        try:
            doc.build(elements, onFirstPage=add_footer, onLaterPages=add_footer)
            return True, save_path
        except Exception as e:
            return False, str(e)

    def generate_site_report(self, site_data, dashboard, devices, save_path=None):
        """Generate a corporate PDF report for a specific network site and its assets."""
        import html

        if not save_path:
            save_path = os.path.join(os.path.expanduser("~"), "Desktop", "BahaaIT_Site_Report.pdf")

        site_name = html.escape(str(site_data.get("name", "Site")), quote=False)
        doc = SimpleDocTemplate(
            save_path,
            pagesize=letter,
            title=f"BahaaIT Site Report - {site_name}",
            author="BahaaIT Network Tools",
            creator="BahaaIT Network Tools",
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=54,
        )
        elements = [self._build_corporate_header(f"Rapport Infrastructure Site : {site_name}"), Spacer(1, 12)]

        avail = float(dashboard.get("availability_pct", 0.0) or 0.0)
        lat = dashboard.get("avg_latency_ms")
        lat_str = f"{lat:.1f} ms" if lat is not None else "N/A"
        kpi_data = [
            [
                Paragraph("<b>DISPONIBILITÉ SITE</b>", self.styles["KPITitle"]),
                "",
                Paragraph("<b>ÉQUIPEMENTS (UP/DEG/OFF)</b>", self.styles["KPITitle"]),
                "",
                Paragraph("<b>INCIDENTS / LATENCE MOY.</b>", self.styles["KPITitle"]),
            ],
            [
                Paragraph(f"<font color='#10B981'><b>{avail:.1f}%</b></font>", self.styles["KPIValue"]),
                "",
                Paragraph(
                    f"<font color='#10B981'><b>{dashboard.get('online_devices', 0)}</b></font> / "
                    f"<font color='#F59E0B'><b>{dashboard.get('degraded_devices', 0)}</b></font> / "
                    f"<font color='#EF4444'><b>{dashboard.get('offline_devices', 0)}</b></font>",
                    self.styles["KPIValue"],
                ),
                "",
                Paragraph(
                    f"<font color='#6366F1'><b>{dashboard.get('active_incidents', 0)}</b></font> "
                    f"<font size='8' color='#64748B'>• {lat_str}</font>",
                    self.styles["KPIValue"],
                ),
            ],
        ]
        kpi_tbl = Table(kpi_data, colWidths=[166, 16, 166, 16, 166])
        kpi_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (0, -1), 1, colors.HexColor("#E2E8F0")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (2, 0), (2, -1), 1, colors.HexColor("#E2E8F0")),
            ("BACKGROUND", (4, 0), (4, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (4, 0), (4, -1), 1, colors.HexColor("#E2E8F0")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(kpi_tbl)
        elements.append(Spacer(1, 10))

        ranges = ", ".join(str(r) for r in (site_data.get("network_ranges") or [])) or "—"
        dns_list = ", ".join(str(d) for d in (site_data.get("dns_servers") or [])) or "—"
        meta_rows = [
            [
                Paragraph("<b>Organisation / Région :</b>", self.styles["MetaTitle"]),
                Paragraph(
                    f"{html.escape(str(site_data.get('organization', '')), quote=False)} / "
                    f"{html.escape(str(site_data.get('region', '')), quote=False)}",
                    self.styles["MetaText"],
                ),
                Paragraph("<b>Connectivité / WAN :</b>", self.styles["MetaTitle"]),
                Paragraph(
                    f"{html.escape(str(site_data.get('connectivity_mode', 'LOCAL')), quote=False)} "
                    f"({html.escape(str(dashboard.get('wan_status', 'UNKNOWN')), quote=False)})",
                    self.styles["MetaText"],
                ),
            ],
            [
                Paragraph("<b>Adresse / Contact :</b>", self.styles["MetaTitle"]),
                Paragraph(
                    f"{html.escape(str(site_data.get('address') or '—'), quote=False)} | "
                    f"{html.escape(str(site_data.get('contact_name') or '—'), quote=False)}",
                    self.styles["MetaText"],
                ),
                Paragraph("<b>Passerelle / FAI :</b>", self.styles["MetaTitle"]),
                Paragraph(
                    f"{html.escape(str(site_data.get('default_gateway') or '—'), quote=False)} | "
                    f"{html.escape(str(site_data.get('isp_name') or '—'), quote=False)}",
                    self.styles["MetaText"],
                ),
            ],
            [
                Paragraph("<b>Plages Réseau :</b>", self.styles["MetaTitle"]),
                Paragraph(html.escape(ranges, quote=False), self.styles["MetaText"]),
                Paragraph("<b>Serveurs DNS / VLANs :</b>", self.styles["MetaTitle"]),
                Paragraph(f"{html.escape(dns_list, quote=False)} ({dashboard.get('vlan_count', 0)} VLANs)", self.styles["MetaText"]),
            ],
        ]
        meta_tbl = Table(meta_rows, colWidths=[110, 155, 110, 155])
        meta_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(meta_tbl)
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("<b>ÉQUIPEMENTS ASSOCIÉS AU SITE</b>", self.styles["SectionHeader"]))
        if devices:
            elements.append(self._build_device_inventory_table(devices))
        else:
            elements.append(Paragraph("Aucun équipement rattaché à ce site.", self.styles["MetaText"]))

        def add_footer(canvas, doc_obj):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
            canvas.setLineWidth(0.5)
            canvas.line(36, 40, doc_obj.pagesize[0] - 36, 40)
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#64748B"))
            canvas.drawString(36, 25, f"BahaaIT Network Tools — Rapport Site ({site_data.get('name', '')})")
            canvas.drawRightString(doc_obj.pagesize[0] - 36, 25, f"Page {canvas.getPageNumber()}")
            canvas.restoreState()

        try:
            doc.build(elements, onFirstPage=add_footer, onLaterPages=add_footer)
            return True, save_path
        except Exception as e:
            return False, str(e)
