import os
import csv
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from backend.config import Config
from backend.utils.helpers import get_db_connection, row_to_dict
from backend.utils.logger import logger

class ReportService:
    @staticmethod
    def generate_pdf_report(filename="threat_audit_report.pdf"):
        """
        Compiles a professional PDF threat report using ReportLab.
        """
        filepath = os.path.join(Config.REPORTS_FOLDER, filename)
        
        # 1. Fetch statistics and prediction history
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM metrics ORDER BY timestamp DESC LIMIT 1")
        latest_metrics = dict(cursor.fetchone())
        
        cursor.execute("SELECT * FROM predictions ORDER BY timestamp DESC LIMIT 10")
        recent_preds = [row_to_dict(r) for r in cursor.fetchall()]
        
        cursor.execute("SELECT COUNT(*), prediction FROM predictions GROUP BY prediction")
        class_counts = dict(cursor.fetchall())
        conn.close()
        
        # 2. Build PDF Document
        doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        story = []
        
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            textColor=colors.HexColor('#0F172A'),
            spaceAfter=15
        )
        
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#475569'),
            spaceAfter=25
        )
        
        section_heading = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            textColor=colors.HexColor('#1E3A8A'),
            spaceBefore=15,
            spaceAfter=10
        )
        
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#334155'),
            leading=14
        )
        
        # Header Banner
        story.append(Paragraph("AI-BASED INTRUSION DETECTION SYSTEM", title_style))
        story.append(Paragraph(f"SOC Threat Operations Audit Log | Compiled: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
        story.append(Spacer(1, 10))
        
        # Section: Dashboard Metrics Overview
        story.append(Paragraph("1. System Metrics Summary", section_heading))
        metrics_data = [
            ["Parameter Indicator", "Value", "Remediation Alert Level"],
            ["Total Inspected Packets", f"{latest_metrics['total_packets']:,}", "Active Monitoring"],
            ["Normal Traffic Packets", f"{latest_metrics['normal_packets']:,}", "Safe State"],
            ["Malicious Attack Packets", f"{latest_metrics['malicious_packets']:,}", "Quarantined Node"],
            ["Machine Learning Accuracy", f"{latest_metrics['accuracy']:.2f}%", "XGBoost Optimized"],
            ["False Ingress Alarm Rate", f"{latest_metrics['fpr']:.2f}%", "System Baseline Calibration"],
            ["Current Node Threat Index", latest_metrics['threat_level'], "Moderate Warnings Threshold"]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[200, 150, 150])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E3A8A')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#F8FAFC')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('TEXTCOLOR', (1,3), (1,3), colors.HexColor('#EF4444')), # Malicious text red
            ('TEXTCOLOR', (2,3), (2,3), colors.HexColor('#EF4444')), 
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 20))
        
        # Section: Attacks Classification Distribution
        story.append(Paragraph("2. Threats Distribution Ratio", section_heading))
        normal_cnt = class_counts.get("Normal", 0)
        attack_cnt = class_counts.get("Attack", 0)
        susp_cnt = class_counts.get("Suspicious", 0)
        total_cnt = normal_cnt + attack_cnt + susp_cnt
        
        dist_desc = f"Out of {total_cnt:,} analyzed predictions registered, normal flows make up {normal_cnt:,} packets. Malicious attacks and suspicious port activities represent {attack_cnt + susp_cnt:,} instances."
        story.append(Paragraph(dist_desc, body_style))
        story.append(Spacer(1, 10))
        
        # Section: Prediction Logs
        story.append(Paragraph("3. Recent Log Audits (Last 10 Records)", section_heading))
        log_headers = ["Flow ID", "Src IP", "Dst IP", "Port", "Prediction", "Confidence"]
        log_rows = [log_headers]
        
        for p in recent_preds:
            log_rows.append([
                p["flow_id"],
                p["src_ip"],
                p["dst_ip"],
                str(p["port"]),
                p["prediction"],
                f"{p['confidence']}%"
            ])
            
        log_table = Table(log_rows, colWidths=[70, 95, 95, 50, 90, 80])
        log_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 5),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('BACKGROUND', (0,1), (-1,-1), colors.white),
        ]))
        story.append(log_table)
        
        # Build Document
        doc.build(story)
        logger.info(f"Successfully generated PDF report file at {filepath}")
        return filepath

    @staticmethod
    def generate_csv_report(filename="threat_audit_report.csv"):
        """Compiles standard CSV prediction history download."""
        filepath = os.path.join(Config.REPORTS_FOLDER, filename)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT flow_id, timestamp, src_ip, dst_ip, protocol, port, prediction, confidence, risk_level, attack_type FROM predictions ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        conn.close()
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Flow ID", "Timestamp", "Source IP", "Destination IP", "Protocol", "Port", "Prediction", "Confidence Score", "Risk Level", "Attack Class"])
            for row in rows:
                writer.writerow(row)
                
        logger.info(f"Successfully generated CSV report file at {filepath}")
        return filepath

    @staticmethod
    def generate_json_report(filename="threat_audit_report.json"):
        """Compiles standard JSON threat aggregates export."""
        filepath = os.path.join(Config.REPORTS_FOLDER, filename)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM predictions ORDER BY timestamp DESC")
        rows = [row_to_dict(r) for r in cursor.fetchall()]
        conn.close()
        
        with open(filepath, 'w') as f:
            json.dump(rows, f, indent=4)
            
        logger.info(f"Successfully generated JSON report file at {filepath}")
        return filepath
