import json
import os
from typing import Dict, Any
from datetime import datetime
from mcp_diagram_generator import MCPDiagramGenerator

class ReportAgent:
    """LLM-powered comprehensive threat modeling report generation"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.reports_dir = "reports"
        self.diagram_generator = MCPDiagramGenerator(self.llm)
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def clean_llm_response(self, content: str) -> str:
        """Remove unwanted content from LLM responses"""
        import re
        
        # Remove markdown code blocks (all variations)
        content = re.sub(r'```[a-zA-Z]*\n?', '', content)  # Opening blocks
        content = re.sub(r'\n?```\s*$', '', content)        # Closing blocks at end
        content = re.sub(r'```', '', content)              # Any remaining backticks
        
        # Remove instruction blocks
        content = re.sub(r'<implicitInstruction>.*?</implicitInstruction>', '', content, flags=re.DOTALL | re.IGNORECASE)
        content = re.sub(r'<activeFile>.*?</activeFile>', '', content, flags=re.DOTALL | re.IGNORECASE)
        
        # Fix HTML entities
        content = content.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#39;', "'")
        
        # Clean up extra whitespace
        content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)
        
        return content.strip()
    
    async def generate_comprehensive_report(self, all_data: Dict[str, Any]) -> str:
        """Generate complete threat modeling report from all collected data"""
        
        report_prompt = f"""
        Generate a technical threat modeling report based on the collected data.
        
        COLLECTED DATA:
        {json.dumps(all_data, indent=2)}
        
        
        Create a threat modeling report with these sections:
        
        1. EXECUTIVE SUMMARY
           - Key vulnerabilities found
           - Critical risks identified
           - Immediate actions needed
        
        2. PRODUCT OVERVIEW
           - Technical components
           - Attack surface
           - Dependencies
        
        3. THREAT ANALYSIS
           - Recent CVE vulnerabilities with CVSS scores
           - Attack trends
           - Threat intelligence findings
        
        4. ATTACK SCENARIOS
           Create 2 realistic attack scenarios based on the top 3 threats. For each scenario:
           
           SCENARIO A: [Attack Type]
           Step 1: [Attack Step] (MITRE T####)
           Step 2: [Attack Step] (MITRE T####)
           Step 3: [Attack Step] (MITRE T####)
           [Continue with all steps]
           
           For each step include:
           - Technical details
           - Tools used
           - Detection methods
           
           IMPORTANT: End each scenario with: [DIAGRAM_PLACEHOLDER_SCENARIO_X]
           This will be replaced with the attack flow diagram for that specific scenario.
        
        5. SECURITY CONTROLS
           Map controls to attack steps:
           "MFA mitigates Step 4 by preventing credential reuse"
           
           Include:
           - Technical controls
           - Administrative controls
           - Implementation priority
        
        Format as structured technical text with clear sections.
        Use HTML formatting with proper tags for headings, paragraphs, lists, and emphasis.
        Make this report technical and actionable for security analysts.
        
        OUTPUT FORMAT: Generate the report content as HTML with proper tags:
        - Use <h1> for main sections (1. EXECUTIVE SUMMARY, etc.)
        - Use <h2> for subsections
        - Use <h3> for sub-subsections
        - Use <p> for paragraphs
        - Use <ul><li> for bullet points
        - Use <ol><li> for numbered lists
        - Use <strong> for emphasis on critical items
        - Use <span class="critical"> for high-risk items
        - Use <span class="mitre"> for MITRE technique references
        """
        
        report_content = await self.llm.generate(report_prompt, max_tokens=2000)
        
        # Clean up LLM response - remove unwanted content
        report_content = self.clean_llm_response(report_content)
        
        # Ensure proper HTML structure if LLM didn't provide it
        if not report_content.strip().startswith('<'):
            report_content = f"<div class='report-content'>{report_content}</div>"
        
        # Add diagrams after each attack scenario
        threats = all_data.get('threats', [])
        product_name = all_data.get('product_name', 'Unknown Product')
        
        # Generate individual diagrams for each scenario
        async with self.diagram_generator as mcp_gen:
            report_content = await mcp_gen.insert_scenario_diagrams(threats, product_name, report_content)
            diagrams_html = ""  # No additional diagrams section
        
        return report_content + diagrams_html
    
    def save_html_report(self, report_content: str, product_name: str) -> str:
        """Save report as professional HTML webpage"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_product_name = product_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
        filename = f"{safe_product_name}_ThreatModel_{timestamp}.html"
        filepath = os.path.join(self.reports_dir, filename)
        
        try:
            html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Modeling Assessment - {product_name}</title>
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
            box-shadow: 0 25px 50px rgba(0,0,0,0.15), 0 0 0 1px rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid transparent;
            background: linear-gradient(90deg, #667eea, #764ba2) padding-box,
                       linear-gradient(90deg, #667eea, #764ba2) border-box;
            border-image: linear-gradient(90deg, #667eea, #764ba2) 1;
            padding-bottom: 40px;
            margin-bottom: 50px;
            position: relative;
        }}
        .header::after {{
            content: '';
            position: absolute;
            bottom: -3px;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #667eea, #764ba2);
        }}
        .header h1 {{
            color: #2c3e50;
            font-size: 2.5em;
            margin: 0;
            font-weight: bold;
        }}
        .header h2 {{
            color: #34495e;
            font-size: 1.8em;
            margin: 10px 0;
        }}
        .header .product {{
            font-size: 1.2em;
            color: #7f8c8d;
            margin: 15px 0;
        }}
        .header .confidential {{
            color: #e74c3c;
            font-weight: bold;
            font-size: 1.1em;
            margin-top: 20px;
        }}
        h1 {{
            color: #2c3e50;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            border-bottom: 3px solid transparent;
            border-image: linear-gradient(90deg, #667eea, #764ba2) 1;
            padding-bottom: 15px;
            margin-top: 50px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-left: 4px solid #3498db;
            padding-left: 15px;
        }}
        h3 {{
            color: #2c3e50;
            margin-top: 25px;
        }}
        p {{
            margin: 15px 0;
            text-align: justify;
        }}
        ul, ol {{
            margin: 15px 0;
            padding-left: 30px;
        }}
        li {{
            margin: 8px 0;
        }}
        .critical {{
            color: #c0392b;
            font-weight: bold;
            background-color: #fadbd8;
            padding: 3px 8px;
            border-radius: 4px;
            border-left: 4px solid #e74c3c;
        }}
        .mitre {{
            background-color: #eaf2f8;
            color: #1b4f72;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .cvss-score {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            color: white;
            font-weight: bold;
            font-size: 0.85em;
        }}
        .cvss-critical {{ background-color: #8b0000; }}
        .cvss-high {{ background-color: #dc143c; }}
        .cvss-medium {{ background-color: #ff8c00; }}
        .cvss-low {{ background-color: #32cd32; }}
        .scenario {{
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 20px;
            margin: 20px 0;
        }}
        .risk-matrix {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
        }}
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #bdc3c7;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .mermaid {{
            text-align: center;
            margin: 20px 0;
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 20px;
        }}
        @media print {{
            body {{ background-color: white; }}
            .container {{ box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CYBERSECURITY THREAT ASSESSMENT</h1>
            <h2>EXECUTIVE RISK ANALYSIS</h2>
            <div class="product">Product: {product_name}</div>
            <div>Assessment Date: {datetime.now().strftime("%B %d, %Y")}</div>
            <div class="confidential">CONFIDENTIAL - INTERNAL USE ONLY</div>
        </div>
        
        <div class="content">
            {report_content}
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
        <script>
            mermaid.initialize({{
                startOnLoad: true,
                theme: 'default',
                securityLevel: 'loose'
            }});
        </script>
        
        <div class="footer">
            <p>Confidential - {product_name} Threat Assessment - Generated on {datetime.now().strftime("%B %d, %Y at %I:%M %p")}</p>
        </div>
    </div>
</body>
</html>
            """
            
            # Ensure report content is properly formatted
            if not report_content or report_content.strip() == "":
                report_content = "<h1>Report Generation Error</h1><p>No content was generated. Please try again.</p>"
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_template)
            
            print(f"   📄 HTML report saved: {filepath}")
            
            return filepath
            
        except Exception as e:
            print(f"Error creating HTML report: {e}")
            return f"HTML report creation failed: {e}"