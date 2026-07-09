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
