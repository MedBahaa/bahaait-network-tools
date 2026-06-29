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

    def generate_monitor_report(self, data, save_path=None, event_log_text=None):
        if not save_path:
            save_path = os.path.join(os.path.expanduser("~"), "Desktop", self.filename)
            
        doc = SimpleDocTemplate(
            save_path,
            pagesize=letter,
            title="BahaaIT Network Diagnostics Report",
            author="BahaaIT Network Tools",
            creator="BahaaIT Network Tools"
        )
        elements = []
        
        # Logo & Header
        import sys
        if getattr(sys, 'frozen', False):
            logo_path = os.path.join(sys._MEIPASS, "src", "assets", "logo.png")
        else:
            logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png"))
            
        if os.path.exists(logo_path):
            logo = Image(logo_path, width=50, height=50)
            logo.hAlign = 'CENTER'
            elements.append(logo)
            elements.append(Spacer(1, 10))

        elements.append(Paragraph("BahaaIT Network Tools", self.styles['ReportTitle']))
        elements.append(Paragraph(_("pdf_monitor_subtitle"), self.styles['Subtitle']))
        elements.append(Paragraph(_("pdf_generated").format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')), self.styles['Subtitle']))
        elements.append(Spacer(1, 20))
        
        # Data Table
        table_data = [[_("pdf_table_device"), _("pdf_table_ip"), _("pdf_table_status"), _("pdf_table_latency")]]
        
        # data is expected to be a list of dicts: {"label": "Router", "ip": "192.168.1.1", "status": "UP", "latency": 15}
        for item in data:
            status_cell = item.get("status", "N/A")
            latency_cell = f"{item.get('latency', 0)} ms"
            table_data.append([
                item.get("label", "Unknown"),
                item.get("ip", "Unknown"),
                status_cell,
                latency_cell
            ])
            
        table = Table(table_data, colWidths=[120, 150, 100, 100])
        
        # Table Style
        style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 12),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#F8FAFC')),
            ('TEXTCOLOR', (0,1), (-1,-1), colors.black),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1'))
        ])
        
        # Add color logic to cells
        for i, row in enumerate(table_data[1:], start=1):
            if row[2] == "UP":
                style.add('TEXTCOLOR', (2,i), (2,i), colors.HexColor('#10B981')) # Green
            elif row[2] == "DOWN":
                style.add('TEXTCOLOR', (2,i), (2,i), colors.HexColor('#F43F5E')) # Red
                
        table.setStyle(style)
        elements.append(table)
        
        # Add Event Log if provided
        if event_log_text:
            elements.append(Spacer(1, 25))
            
            # Heading for Event Log
            h2_style = ParagraphStyle(
                name='SectionHeader',
                parent=self.styles['Heading2'],
                fontSize=14,
                spaceAfter=10,
                textColor=colors.HexColor('#1E293B')
            )
            elements.append(Paragraph(_("pdf_event_log"), h2_style))
            
            # Formatting log lines
            log_lines = event_log_text.split('\n')
            for line in log_lines:
                line = line.strip()
                if line:
                    elements.append(Paragraph(line, self.styles['LogLine']))
        
        # Build PDF
        try:
            doc.build(elements)
            return True, save_path
        except Exception as e:
            return False, str(e)

    def generate_speedtest_report(self, data, save_path=None):
        if not save_path:
            save_path = os.path.join(os.path.expanduser("~"), "Desktop", "BahaaIT_Speedtest_Report.pdf")
            
        doc = SimpleDocTemplate(
            save_path,
            pagesize=letter,
            title="BahaaIT Speedtest Report",
            author="BahaaIT Network Tools",
            creator="BahaaIT Network Tools"
        )
        elements = []
        
        # Logo & Header
        import sys
        if getattr(sys, 'frozen', False):
            logo_path = os.path.join(sys._MEIPASS, "src", "assets", "logo.png")
        else:
            logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png"))
            
        if os.path.exists(logo_path):
            logo = Image(logo_path, width=50, height=50)
            logo.hAlign = 'CENTER'
            elements.append(logo)
            elements.append(Spacer(1, 10))

        elements.append(Paragraph("BahaaIT Network Tools", self.styles['ReportTitle']))
        elements.append(Paragraph(_("pdf_speedtest_subtitle"), self.styles['Subtitle']))
        elements.append(Paragraph(_("pdf_generated").format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')), self.styles['Subtitle']))
        elements.append(Spacer(1, 20))
        
        # Data Table
        table_data = [[_("pdf_table_datetime"), _("pdf_table_down"), _("pdf_table_up"), _("pdf_table_ping"), _("pdf_table_jitter"), _("pdf_table_loss")]]
        
        for item in data:
            table_data.append([
                item.get("timestamp", "N/A"),
                f"{item.get('download', 0):.2f}",
                f"{item.get('upload', 0):.2f}",
                f"{item.get('ping', 0):.1f}",
                f"{item.get('jitter', 0):.1f}",
                f"{item.get('packet_loss', 0):.1f}"
            ])
            
        table = Table(table_data, colWidths=[130, 80, 80, 70, 70, 70])
        
        # Table Style
        style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#F8FAFC')),
            ('TEXTCOLOR', (0,1), (-1,-1), colors.black),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,1), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1'))
        ])
        
        table.setStyle(style)
        elements.append(table)
        
        # Build PDF
        try:
            doc.build(elements)
            return True, save_path
        except Exception as e:
            return False, str(e)
