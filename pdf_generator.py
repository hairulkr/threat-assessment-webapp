#!/usr/bin/env python3
"""
Alternative PDF generation using WeasyPrint (more reliable than pdfkit)
"""

import base64
import streamlit as st
from io import BytesIO

def create_pdf_with_weasyprint(html_content: str, filename: str):
    """Create PDF using WeasyPrint - disabled due to Windows compatibility issues"""
    return None

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