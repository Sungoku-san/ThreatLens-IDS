import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from backend.config import Config
from backend.utils.logger import logger
from backend.AI.threat_analyzer import ThreatAnalyzer
from backend.AI.recommendation_engine import RecommendationEngine

class AIReportGenerator:
    @staticmethod
    def generate_incident_pdf(flow_data, filename="incident_report.pdf"):
        """
        Generates a professional PDF Incident Report for a specific threat connection.
        """
        filepath = os.path.join(Config.REPORTS_FOLDER, filename)
        
        prediction = flow_data["prediction"]
        attack_type = flow_data["attack_type"]
        confidence = flow_data["confidence"]
        
        # Gather threat metrics
        analysis = ThreatAnalyzer.analyze_threat(prediction, attack_type, confidence)
        recs = RecommendationEngine.generate_recommendations(prediction, attack_type, flow_data["src_ip"], flow_data["port"])
        
        # Build ReportLab Doc
        doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
        story = []
        
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            textColor=colors.HexColor('#991B1B') if prediction == "Attack" else colors.HexColor('#0F172A'),
            spaceAfter=15
        )
        
        section_title = ParagraphStyle(
            'SectionTitle',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            textColor=colors.HexColor('#1E3A8A'),
            spaceBefore=12,
            spaceAfter=8
        )
        
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9.5,
            textColor=colors.HexColor('#334155'),
            leading=13
        )
        
        # Document Headers
        story.append(Paragraph(f"AI SECURITY COPILOT: INCIDENT REPORT ({flow_data['flow_id']})", title_style))
        story.append(Paragraph(f"Threat Operations Incident Audit | Compiled: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Table of packet metadata
        meta_data = [
            ["Parameter Indicator", "Connection Metric Details"],
            ["Flow Connection ID", flow_data["flow_id"]],
            ["Source Address IP", flow_data["src_ip"]],
            ["Destination Target IP", flow_data["dst_ip"]],
            ["Protocol Port Interface", f"{flow_data['protocol']} / Port {flow_data['port']}"],
            ["Inference Outcome", prediction.upper()],
            ["Model Confidence Score", f"{confidence:.1f}%"],
            ["MITRE Attack Map Technique", f"{analysis['mitre_technique']} ({analysis['mitre_id']})"]
        ]
        
        meta_table = Table(meta_data, colWidths=[200, 300])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 5),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#F8FAFC')),
        ]))
        
        story.append(meta_table)
        story.append(Spacer(1, 15))
        
        # Section: Incident Description
        story.append(Paragraph("1. Attack Vector & Impact Analysis", section_title))
        desc = f"The connection log from {flow_data['src_ip']} targeting port {flow_data['port']} was classified by the machine learning algorithm as an active threat. **Impact Severity: {analysis['severity']}**. Likelihood of exploit: {analysis['likelihood']}. The threat evaluation shows that: {analysis['impact']}"
        story.append(Paragraph(desc, body_style))
        story.append(Spacer(1, 15))
        
        # Section: AI Decisions Explanations (SHAP)
        story.append(Paragraph("2. Explainable AI (SHAP) Decision Logic", section_title))
        story.append(Paragraph(flow_data["explanation"], body_style))
        story.append(Spacer(1, 15))
        
        # Section: Mitigation Controls
        story.append(Paragraph("3. Recommended Remediation & Defenses Rules", section_title))
        story.append(Paragraph("A. Firewall Block Commands:", styles['Normal']))
        for rule in recs["firewall_rules"]:
            story.append(Paragraph(f"<code>{rule}</code>", body_style))
            
        story.append(Spacer(1, 5))
        story.append(Paragraph("B. Intrusion Detection (Snort Rules):", styles['Normal']))
        for id_rule in recs["ids_rules"]:
            story.append(Paragraph(f"<code>{id_rule}</code>", body_style))
            
        # Build
        doc.build(story)
        logger.info(f"Generated AI PDF incident report at {filepath}")
        return filepath
