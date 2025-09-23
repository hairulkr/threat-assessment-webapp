"""Report formatting and HTML normalization utilities"""
import re
import html
from typing import Dict, Any

class ReportFormatter:
    """Handles consistent formatting and HTML normalization across different LLMs"""
    
    def __init__(self):
        self.html_entities = {
            '&amp;#39;': "'",
            '&amp;': '&',
            '&lt;': '<',
            '&gt;': '>',
            '&quot;': '"',
            '&#39;': "'",
            '&lt;/h2&gt;': '',
            '</h2>': ''
        }
    
    def clean_llm_response(self, content: str) -> str:
        """Remove unwanted content and normalize LLM responses"""
        # Remove markdown code blocks
        content = re.sub(r'```[a-zA-Z]*\n?', '', content)
        content = re.sub(r'\n?```\s*$', '', content)
        content = re.sub(r'```', '', content)
        
        # Remove instruction blocks
        content = re.sub(r'<implicitInstruction>.*?</implicitInstruction>', '', content, flags=re.DOTALL | re.IGNORECASE)
        content = re.sub(r'<activeFile>.*?</activeFile>', '', content, flags=re.DOTALL | re.IGNORECASE)
        
        # Fix HTML entities - comprehensive cleaning
        for entity, replacement in self.html_entities.items():
            content = content.replace(entity, replacement)
        
        # Additional HTML entity cleaning - but preserve valid HTML structure
        content = re.sub(r'&[a-zA-Z0-9#]+;(?![a-zA-Z0-9#]*>)', '', content)  # Remove entities but not in tags
        
        # Clean up whitespace
        content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)
        
        return content.strip()
    
    def normalize_html_structure(self, content: str) -> str:
        """Ensure consistent HTML structure across different LLMs"""
        # Convert plain text sections to proper HTML
        lines = content.split('\n')
        formatted_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                formatted_lines.append('')
                continue
                
            # Main headers
            if line.upper() in ['EXECUTIVE SUMMARY', 'THREAT INTELLIGENCE ANALYSIS', 'ATTACK SCENARIOS', 'SECURITY CONTROLS & MITIGATIONS']:
                formatted_lines.append(f'<h1>{line}</h1>')
            # Scenario headers
            elif re.match(r'^SCENARIO [A-Z]:', line):
                formatted_lines.append(f'<h2>{line}</h2>')
            # Phase headers
            elif re.match(r'^Phase \d+:', line):
                formatted_lines.append(f'<h3>{line}</h3>')
            # Sub-sections
            elif line.endswith(':') and len(line) < 50:
                formatted_lines.append(f'<h4>{line}</h4>')
            # Regular paragraphs
            elif not line.startswith('<'):
                formatted_lines.append(f'<p>{line}</p>')
            else:
                formatted_lines.append(line)
        
        content = '\n'.join(formatted_lines)
        
        # Fix common markdown leakage
        content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', content)
        
        # Fix unclosed tags (basic validation)
        content = self._fix_unclosed_tags(content)
        
        return content
    
    def _fix_unclosed_tags(self, content: str) -> str:
        """Basic HTML tag validation and fixing"""
        # This is a simplified version - could be enhanced with proper HTML parser
        tag_pairs = [
            ('<h1>', '</h1>'),
            ('<h2>', '</h2>'),
            ('<h3>', '</h3>'),
            ('<p>', '</p>'),
            ('<strong>', '</strong>'),
            ('<ul>', '</ul>'),
            ('<ol>', '</ol>')
        ]
        
        for open_tag, close_tag in tag_pairs:
            open_count = content.count(open_tag)
            close_count = content.count(close_tag)
            
            if open_count > close_count:
                # Add missing closing tags at the end
                content += close_tag * (open_count - close_count)
        
        return content
    
    def create_html_template(self, report_content: str, product_name: str) -> str:
        """Create complete HTML document with proper styling"""
        escaped_product_name = html.escape(product_name)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Modeling Assessment - {escaped_product_name}</title>
    <style>
        body {{
            font-family: 'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.7;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #2c3e50;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.98);
            padding: 50px;
            border-radius: 20px;
            box-shadow: 0 25px 50px rgba(0,0,0,0.15);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
        }}
        .diagram-container {{
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
            border-left: 4px solid #007bff;
        }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .mitre {{ background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
        h1 {{ 
            color: #2c3e50; 
            border-bottom: 3px solid #3498db; 
            padding-bottom: 15px;
            margin-top: 40px;
            margin-bottom: 25px;
            font-size: 2.2em;
        }}
        h2 {{ 
            color: #34495e; 
            margin-top: 35px;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-left: 4px solid #e74c3c;
            padding-left: 15px;
        }}
        h3 {{ 
            color: #5a6c7d;
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 1.4em;
        }}
        h4 {{
            color: #7f8c8d;
            margin-top: 20px;
            margin-bottom: 10px;
            font-size: 1.2em;
        }}
        p {{
            margin-bottom: 15px;
            text-align: justify;
        }}
        .attack-flow {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            font-family: monospace;
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            mermaid.initialize({{ 
                startOnLoad: true,
                theme: 'default',
                securityLevel: 'loose'
            }});
        }});
    </script>
</head>
<body>
    <div class="container">
        {report_content}
    </div>
</body>
</html>"""