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
        
        # Fix HTML entities
        for entity, replacement in self.html_entities.items():
            content = content.replace(entity, replacement)
        
        # Clean up whitespace
        content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)
        
        return content.strip()
    
    def normalize_html_structure(self, content: str) -> str:
        """Ensure consistent HTML structure across different LLMs"""
        # Fix common markdown leakage
        content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', content)
        content = re.sub(r'#{1,6}\s*(.*?)(?=\n|$)', r'<h3>\1</h3>', content)
        
        # Ensure proper HTML wrapper
        if not content.strip().startswith('<'):
            content = f"<div class='report-content'>{content}</div>"
        
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
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        h3 {{ color: #5a6c7d; }}
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