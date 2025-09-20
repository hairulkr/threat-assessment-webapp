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
        
        # Call the DailyUsageTracker to decrement the count after report generation
        from daily_usage_tracker import DailyUsageTracker
        usage_tracker = DailyUsageTracker()
        usage_tracker.increment_usage()
        
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
        .diagram-container {{
            margin: 20px 0;
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            mermaid.initialize({{ startOnLoad: true }});
        }});
    </script>
</head>
<body>
    <div class="container">
        {report_content}
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