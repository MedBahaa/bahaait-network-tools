from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from datetime import datetime
import os

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

    def generate_monitor_report(self, data, save_path=None):
        if not save_path:
            save_path = os.path.join(os.path.expanduser("~"), "Desktop", self.filename)
            
        doc = SimpleDocTemplate(save_path, pagesize=letter)
        elements = []
        
        # Header
        elements.append(Paragraph("BahaaIT Enterprise Suite", self.styles['ReportTitle']))
        elements.append(Paragraph(f"Network Diagnostics & Monitoring Report", self.styles['Subtitle']))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Subtitle']))
        elements.append(Spacer(1, 20))
        
        # Data Table
        table_data = [['Device Name', 'IP/Hostname', 'Status', 'Latency']]
        
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
        
        # Build PDF
        try:
            doc.build(elements)
            return True, save_path
        except Exception as e:
            return False, str(e)

    def generate_speedtest_report(self, data, save_path=None):
        if not save_path:
            save_path = os.path.join(os.path.expanduser("~"), "Desktop", "BahaaIT_Speedtest_Report.pdf")
            
        doc = SimpleDocTemplate(save_path, pagesize=letter)
        elements = []
        
        # Header
        elements.append(Paragraph("BahaaIT Enterprise Suite", self.styles['ReportTitle']))
        elements.append(Paragraph("Network Speed & Performance Report", self.styles['Subtitle']))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Subtitle']))
        elements.append(Spacer(1, 20))
        
        # Data Table
        table_data = [['Date/Time', 'Down (Mbps)', 'Up (Mbps)', 'Ping (ms)', 'Jitter', 'Loss %']]
        
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
