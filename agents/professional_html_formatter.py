"""Professional HTML formatter for threat modeling reports"""
import re
import html
from typing import Dict, Any, List
import markdown
from markdown.extensions import tables, toc, codehilite

class ProfessionalHTMLFormatter:
    """Advanced HTML formatter for professional threat modeling reports"""
    
    def __init__(self):
        self.markdown_processor = markdown.Markdown(
            extensions=['tables', 'toc', 'codehilite', 'fenced_code', 'attr_list'],
            extension_configs={
                'toc': {'title': 'Table of Contents'},
                'codehilite': {'css_class': 'highlight'}
            }
        )
    
    def convert_markdown_to_html(self, content: str) -> str:
        """Convert markdown content to professional HTML"""
        # Clean up the content first
        content = self._preprocess_content(content)
        
        # Convert markdown to HTML
        html_content = self.markdown_processor.convert(content)
        
        # Post-process for professional formatting
        html_content = self._postprocess_html(html_content)
        
        return html_content
    
    def _preprocess_content(self, content: str) -> str:
        """Preprocess content before markdown conversion"""
        # Remove any existing HTML tags that might interfere
        content = re.sub(r'<(?!/?(?:strong|em|code|pre|ul|ol|li|h[1-6]|p|br|hr))[^>]*>', '', content)
        
        # Ensure proper markdown formatting for headers
        content = re.sub(r'^([A-Z\s]+)$', r'# \1', content, flags=re.MULTILINE)
        content = re.sub(r'^(SCENARIO [A-Z]:.*?)$', r'## \1', content, flags=re.MULTILINE)
        content = re.sub(r'^(Phase \d+:.*?)$', r'### \1', content, flags=re.MULTILINE)
        
        # Format threat intelligence sections
        content = re.sub(r'^\*\*(.*?)\*\*:', r'#### \1', content, flags=re.MULTILINE)
        
        # Ensure proper list formatting
        content = re.sub(r'^- ', r'* ', content, flags=re.MULTILINE)
        
        # Format MITRE ATT&CK references
        content = re.sub(r'\b(T\d{4}(?:\.\d{3})?)\b', r'`\1`{.mitre-technique}', content)
        
        # Format CVE references with proper HTML
        content = re.sub(r'\*\*(CVE-\d{4}-\d{4,})\*\*\{?\.?cve-id\}?', r'<span class="cve-badge">\1</span>', content)
        content = re.sub(r'\b(CVE-\d{4}-\d{4,})\b', r'<span class="cve-badge">\1</span>', content)
        
        return content
    
    def _postprocess_html(self, html_content: str) -> str:
        """Post-process HTML for professional styling"""
        # Fix broken table formatting first
        html_content = self._fix_table_formatting(html_content)
        
        # Add CSS classes to elements
        html_content = re.sub(r'<h1>', r'<h1 class="main-header">', html_content)
        html_content = re.sub(r'<h2>', r'<h2 class="section-header">', html_content)
        html_content = re.sub(r'<h3>', r'<h3 class="subsection-header">', html_content)
        html_content = re.sub(r'<h4>', r'<h4 class="detail-header">', html_content)
        
        # Style tables
        html_content = re.sub(r'<table>', r'<table class="threat-table">', html_content)
        
        # Style code blocks for MITRE techniques - handle multiple formats
        html_content = re.sub(r'<code class="mitre-technique">(T\d{4}(?:\.\d{3})?)</code>', 
                             r'<span class="mitre-badge">\1</span>', html_content)
        html_content = re.sub(r'`(T\d{4}(?:\.\d{3})?)`\{?\.?mitre-technique\}?', 
                             r'<span class="mitre-badge">\1</span>', html_content)
        html_content = re.sub(r'(?<!<span class="mitre-badge">)\b(T\d{4}(?:\.\d{3})?)\b(?!</span>)', 
                             r'<span class="mitre-badge">\1</span>', html_content)
        
        # Style CVE references - handle multiple formats
        html_content = re.sub(r'<strong class="cve-id">(CVE-\d{4}-\d{4,})</strong>', 
                             r'<span class="cve-badge">\1</span>', html_content)
        html_content = re.sub(r'\*\*(CVE-\d{4}-\d{4,})\*\*', 
                             r'<span class="cve-badge">\1</span>', html_content)
        html_content = re.sub(r'(?<!<span class="cve-badge">)\b(CVE-\d{4}-\d{4,})\b(?!</span>)', 
                             r'<span class="cve-badge">\1</span>', html_content)
        
        # Add severity indicators
        html_content = re.sub(r'\b(CRITICAL|HIGH|MEDIUM|LOW)\b', 
                             r'<span class="severity-\1">\1</span>', html_content, flags=re.IGNORECASE)
        
        return html_content
    
    def _fix_table_formatting(self, content: str) -> str:
        """Fix broken table formatting from LLM output"""
        # Look for broken table patterns like: # CVE ID Title Severity # cve-2022-30129 ...
        table_pattern = r'#\s*(CVE ID|CVE|Vulnerability).*?#\s*(cve-[\d-]+.*?)(?=\n\n|\n#|$)'
        
        def fix_table_match(match):
            table_content = match.group(0)
            
            # Split into lines and clean
            lines = [line.strip() for line in table_content.split('\n') if line.strip()]
            
            if len(lines) < 2:
                return table_content
            
            # Extract header
            header_line = lines[0].replace('#', '').strip()
            headers = [h.strip() for h in re.split(r'\s{2,}|\t', header_line) if h.strip()]
            
            if not headers:
                headers = ['CVE ID', 'Title', 'Severity', 'CVSS Score', 'Source', 'Exploit Available', 'Description']
            
            # Build proper table
            table_html = '<table class="threat-table">\n<thead>\n<tr>\n'
            for header in headers:
                table_html += f'<th>{header}</th>\n'
            table_html += '</tr>\n</thead>\n<tbody>\n'
            
            # Process data rows
            for line in lines[1:]:
                if not line or line.startswith('#'):
                    continue
                    
                # Clean and split row data
                row_data = line.replace('#', '').strip()
                
                # Try to extract CVE ID and other fields
                cve_match = re.search(r'(cve-[\d-]+)', row_data, re.IGNORECASE)
                if cve_match:
                    cve_id = cve_match.group(1).upper()
                    remaining = row_data.replace(cve_match.group(1), '').strip()
                    
                    # Split remaining fields
                    fields = [f.strip() for f in re.split(r'\s{2,}|\t', remaining) if f.strip()]
                    
                    table_html += '<tr>\n'
                    table_html += f'<td><span class="cve-badge">{cve_id}</span></td>\n'
                    
                    # Add remaining fields
                    for i, field in enumerate(fields[:6]):
                        if i == 1 and field.upper() in ['HIGH', 'MEDIUM', 'LOW', 'CRITICAL']:
                            table_html += f'<td><span class="severity-{field.upper()}">{field}</span></td>\n'
                        else:
                            table_html += f'<td>{field}</td>\n'
                    
                    # Fill missing columns
                    for _ in range(len(headers) - len(fields) - 1):
                        table_html += '<td>-</td>\n'
                    
                    table_html += '</tr>\n'
            
            table_html += '</tbody>\n</table>\n'
            return table_html
        
        # Apply table fixes
        content = re.sub(table_pattern, fix_table_match, content, flags=re.DOTALL | re.IGNORECASE)
        
        return content
    
    def create_professional_template(self, report_content: str, product_name: str) -> str:
        """Create a professional HTML document with advanced styling"""
        escaped_product_name = html.escape(product_name)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Modeling Assessment - {escaped_product_name}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        :root {{
            --primary-color: #2563eb;
            --secondary-color: #64748b;
            --success-color: #059669;
            --warning-color: #d97706;
            --danger-color: #dc2626;
            --critical-color: #991b1b;
            --background-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --card-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
            line-height: 1.7;
            color: #1f2937;
            background: var(--background-gradient);
            min-height: 100vh;
            padding: 2rem;
        }}
        
        *, *::before, *::after {{
            font-family: inherit !important;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.98);
            border-radius: 24px;
            box-shadow: var(--card-shadow);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%);
            color: white;
            padding: 3rem 3rem 2rem;
            text-align: center;
            position: relative;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.3;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            position: relative;
            z-index: 1;
        }}
        
        .header .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
            position: relative;
            z-index: 1;
        }}
        
        .content {{
            padding: 3rem;
        }}
        
        .main-header {{
            color: var(--primary-color);
            font-size: 2rem;
            font-weight: 600;
            margin: 2.5rem 0 1.5rem;
            padding-bottom: 0.75rem;
            border-bottom: 3px solid var(--primary-color);
            position: relative;
        }}
        
        .main-header::before {{
            content: '🛡️';
            margin-right: 0.5rem;
        }}
        
        .section-header {{
            color: #374151;
            font-size: 1.5rem;
            font-weight: 600;
            margin: 2rem 0 1rem;
            padding: 1rem 1.5rem;
            background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%);
            border-left: 4px solid var(--danger-color);
            border-radius: 0 8px 8px 0;
        }}
        
        .subsection-header {{
            color: #4b5563;
            font-size: 1.25rem;
            font-weight: 500;
            margin: 1.5rem 0 0.75rem;
            padding-left: 1rem;
            border-left: 3px solid var(--warning-color);
        }}
        
        .detail-header {{
            color: #6b7280;
            font-size: 1.1rem;
            font-weight: 500;
            margin: 1rem 0 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        p {{
            margin-bottom: 1rem;
            text-align: justify;
            line-height: 1.8;
        }}
        
        ul, ol {{
            margin: 1rem 0;
            padding-left: 2rem;
        }}
        
        li {{
            margin-bottom: 0.5rem;
            line-height: 1.6;
        }}
        
        .threat-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1.5rem 0;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        
        .threat-table th {{
            background: linear-gradient(135deg, #374151 0%, #1f2937 100%);
            color: white;
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-size: 0.875rem;
        }}
        
        .threat-table td {{
            padding: 1rem;
            border-bottom: 1px solid #e5e7eb;
        }}
        
        .threat-table tr:hover {{
            background: #f9fafb;
        }}
        
        .mitre-badge {{
            background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-family: 'Inter', 'Monaco', 'Menlo', monospace !important;
            font-size: 0.875rem;
            font-weight: 500;
            display: inline-block;
            margin: 0.125rem;
        }}
        
        .cve-badge {{
            background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-family: 'Inter', 'Monaco', 'Menlo', monospace !important;
            font-size: 0.875rem;
            font-weight: 500;
            display: inline-block;
            margin: 0.125rem;
        }}
        
        .severity-CRITICAL {{
            background: var(--critical-color);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .severity-HIGH {{
            background: var(--danger-color);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .severity-MEDIUM {{
            background: var(--warning-color);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .severity-LOW {{
            background: var(--success-color);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .diagram-container {{
            margin: 2rem 0;
            padding: 2rem;
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            border-radius: 16px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        
        .diagram-container h3 {{
            color: var(--primary-color);
            margin-bottom: 1rem;
            font-size: 1.25rem;
            font-weight: 600;
        }}
        
        .mermaid {{
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            border: 1px solid #e5e7eb;
        }}
        
        .executive-summary {{
            background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%);
            border: 1px solid #a7f3d0;
            border-radius: 16px;
            padding: 2rem;
            margin: 2rem 0;
        }}
        
        .key-findings {{
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            border: 1px solid #f59e0b;
            border-radius: 16px;
            padding: 2rem;
            margin: 2rem 0;
        }}
        
        .recommendations {{
            background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%);
            border: 1px solid #3b82f6;
            border-radius: 16px;
            padding: 2rem;
            margin: 2rem 0;
        }}
        
        @media (max-width: 768px) {{
            body {{
                padding: 1rem;
            }}
            
            .container {{
                border-radius: 16px;
            }}
            
            .header {{
                padding: 2rem 1.5rem 1.5rem;
            }}
            
            .header h1 {{
                font-size: 2rem;
            }}
            
            .content {{
                padding: 2rem 1.5rem;
            }}
            
            .main-header {{
                font-size: 1.75rem;
            }}
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .container {{
                box-shadow: none;
                border: none;
            }}
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            mermaid.initialize({{ 
                startOnLoad: true,
                theme: 'default',
                securityLevel: 'loose',
                flowchart: {{
                    useMaxWidth: true,
                    htmlLabels: true
                }}
            }});
        }});
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Threat Modeling Assessment</h1>
            <div class="subtitle">{escaped_product_name} • Security Analysis Report</div>
        </div>
        <div class="content">
            {report_content}
        </div>
    </div>
</body>
</html>"""