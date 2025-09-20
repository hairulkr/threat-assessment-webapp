#!/usr/bin/env python3
"""
Alternative PDF generation using WeasyPrint (more reliable than pdfkit)
"""

import base64
import streamlit as st
from io import BytesIO

def create_pdf_with_weasyprint(html_content: str, filename: str):
    """Create PDF using WeasyPrint with proper styling"""
    try:
        from weasyprint import HTML, CSS
        from weasyprint.text.fonts import FontConfiguration
        from io import BytesIO
        import base64
        
        # Configure fonts
        font_config = FontConfiguration()
        
        # Add CSS styling to match the HTML report
        css = CSS(string='''
            @page {
                margin: 1cm;
                @top-center {
                    content: string(chapter);
                }
            }
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #2c3e50;
            }
            h1 {
                color: #2c3e50;
                font-size: 24px;
                margin-bottom: 20px;
                string-set: chapter content();
            }
            h2 {
                color: #34495e;
                font-size: 20px;
                margin-top: 30px;
            }
            h3 {
                color: #34495e;
                font-size: 18px;
            }
            .diagram-container {
                margin: 20px 0;
                padding: 15px;
                background-color: #f8f9fa;
                border-radius: 5px;
            }
            .mermaid {
                background: white;
                padding: 10px;
                border-radius: 5px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            th, td {
                padding: 12px;
                border: 1px solid #ddd;
                text-align: left;
            }
            th {
                background-color: #f8f9fa;
                font-weight: bold;
            }
            code {
                background: #f8f9fa;
                padding: 2px 4px;
                border-radius: 3px;
                font-family: monospace;
            }
            .severity-high {
                color: #dc3545;
                font-weight: bold;
            }
            .severity-medium {
                color: #ffc107;
                font-weight: bold;
            }
            .severity-low {
                color: #28a745;
                font-weight: bold;
            }
        ''')
        
        # Create PDF
        buffer = BytesIO()
        HTML(string=html_content).write_pdf(
            buffer,
            stylesheets=[css],
            font_config=font_config
        )
        
        # Get PDF content
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        # Create download link
        b64 = base64.b64encode(pdf_bytes).decode()
        pdf_filename = filename.replace('.html', '.pdf')
        href = f'<a href="data:application/pdf;base64,{b64}" download="{pdf_filename}" class="download-btn">📥 Download PDF Report</a>'
        return href
        
    except ImportError:
        print("WeasyPrint not installed, falling back to simple PDF...")
        return create_simple_pdf(html_content, filename)
    except Exception as e:
        print(f"WeasyPrint PDF generation failed: {e}")
        return create_simple_pdf(html_content, filename)

def create_simple_pdf(html_content: str, filename: str):
    """Fallback: Create simplified PDF using reportlab"""
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from bs4 import BeautifulSoup
        import re
        
        # Parse HTML content
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract text content
        title = soup.find('h1')
        title_text = title.get_text() if title else "Threat Assessment Report"
        
        # Get all text content
        body_text = soup.get_text()
        
        # Clean up text
        body_text = re.sub(r'\n\s*\n', '\n\n', body_text)
        body_text = body_text.strip()
        
        # Create PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.75*inch)
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            textColor='#2c3e50'
        )
        
        # Build PDF content
        story = []
        story.append(Paragraph(title_text, title_style))
        story.append(Spacer(1, 20))
        
        # Add body text in chunks
        paragraphs = body_text.split('\n\n')
        for para in paragraphs[:50]:  # Limit to prevent huge PDFs
            if para.strip():
                story.append(Paragraph(para.strip(), styles['Normal']))
                story.append(Spacer(1, 12))
        
        # Build PDF
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        # Create download link
        b64 = base64.b64encode(pdf_bytes).decode()
        pdf_filename = filename.replace('.html', '.pdf')
        href = f'<a href="data:application/pdf;base64,{b64}" download="{pdf_filename}">📥 Download PDF Report</a>'
        return href
        
    except ImportError:
        return None
    except Exception as e:
        st.error(f"Simple PDF generation failed: {e}")
        return None