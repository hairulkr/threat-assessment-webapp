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
    
    def determine_scenario_types(self, threats):
        """Let LLM determine scenario types dynamically based on threat intelligence"""
        # Return empty list - let LLM analyze threats and create scenarios dynamically
        return []
    
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
    
    async def parse_and_generate_diagrams(self, report_content: str, threats, product_name: str) -> str:
        """Parse scenarios from content and generate appropriate diagrams"""
        import re
        
        print("🔍 Parsing scenarios from report content...")
        
        # Find all scenario patterns - multiple formats
        scenario_patterns = [
            r'SCENARIO\s+([A-Z]):\s*([^\n]+)',  # SCENARIO A: Title
            r'(\d+\.\d+)\s+SCENARIO\s+([A-Z]):\s*([^\n]+)',  # 4.1 SCENARIO A: Title
            r'SCENARIO\s+(\d+):\s*([^\n]+)',  # SCENARIO 1: Title
            r'(\d+\.\d+)\s*([^\n]*?SCENARIO[^\n]*)',  # 4.1 Some Scenario Title
        ]
        
        scenarios_found = []
        
        # Try each pattern to find scenarios
        for pattern in scenario_patterns:
            matches = re.finditer(pattern, report_content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) == 2:  # SCENARIO A: Title format
                    scenario_id = match.group(1)
                    scenario_title = match.group(2)
                elif len(match.groups()) == 3:  # 4.1 SCENARIO A: Title format
                    scenario_id = match.group(2) if match.group(2).isalpha() else match.group(1)
                    scenario_title = match.group(3) if len(match.groups()) == 3 else match.group(2)
                else:
                    continue
                
                # Clean HTML entities from title
                clean_title = scenario_title.replace('&amp;#39;', "'").replace('&amp;lt;', '<').replace('&amp;gt;', '>').replace('&lt;/h2&gt;', '').replace('</h2>', '')
                scenarios_found.append((scenario_id, clean_title.strip()))
        
        # Remove duplicates and sort
        scenarios_found = list(dict.fromkeys(scenarios_found))
        print(f"Found scenarios: {scenarios_found}")
        
        # If no scenarios found, look for any placeholder patterns
        if not scenarios_found:
            placeholders = re.findall(r'\[DIAGRAM_PLACEHOLDER_SCENARIO_([A-Z0-9.]+)\]', report_content)
            scenarios_found = [(pid, f"Scenario {pid}") for pid in placeholders]
            print(f"Found placeholders: {scenarios_found}")
        
        # Generate diagrams for each found scenario
        for scenario_id, scenario_title in scenarios_found:
            print(f"🎯 Generating diagram for Scenario {scenario_id}: {scenario_title}")
            
            # Extract scenario content
            scenario_content = self.extract_scenario_content(report_content, scenario_id, scenario_title)
            print(f"📝 Extracted scenario content length: {len(scenario_content)}")
            print(f"📝 First 200 chars: {scenario_content[:200]}...")
            
            # Generate diagram
            try:
                async with self.diagram_generator as mcp_gen:
                    diagram_html = await mcp_gen.generate_scenario_diagram(scenario_content, scenario_id, threats, product_name)
                print(f"✅ Dynamic diagram generated for {scenario_id}")
            except Exception as e:
                print(f"⚠️ Diagram generation failed for {scenario_id}: {e}")
                print(f"🔄 Using fallback diagram")
                diagram_html = self.create_fallback_diagram(scenario_id, scenario_title, product_name)
            
            # Replace placeholder or insert after scenario
            placeholder_patterns = [
                f'[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id}]',
                f'[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id.upper()}]',
                f'[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id.lower()}]'
            ]
            
            replaced = False
            for placeholder in placeholder_patterns:
                if placeholder in report_content:
                    report_content = report_content.replace(placeholder, diagram_html)
                    replaced = True
                    break
            
            # If no placeholder found, insert after scenario title
            if not replaced:
                scenario_pattern = f"SCENARIO\\s+{re.escape(scenario_id)}[^\\n]*"
                match = re.search(scenario_pattern, report_content, re.IGNORECASE)
                if match:
                    insert_pos = match.end()
                    report_content = report_content[:insert_pos] + "\n" + diagram_html + report_content[insert_pos:]
        
        return report_content
    
    def extract_scenario_content(self, report_content: str, scenario_id: str, scenario_title: str) -> str:
        """Extract scenario content by finding placeholder and working backwards"""
        import re
        
        # Find placeholder position first
        placeholder = f'[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id}]'
        placeholder_pos = report_content.find(placeholder)
        
        if placeholder_pos > 0:
            # Extract content before placeholder (likely the scenario)
            search_start = max(0, placeholder_pos - 3000)
            content_before = report_content[search_start:placeholder_pos]
            
            # Find most recent scenario-like heading
            scenario_patterns = [
                r'\*\*SCENARIO\s+[A-Z]:[^*]*\*\*',
                r'SCENARIO\s+[A-Z]:[^\n]*',
                r'\d+\.\s*SCENARIO\s+[A-Z]:[^\n]*',
                r'<h[23]>[^<]*SCENARIO[^<]*</h[23]>'
            ]
            
            for pattern in scenario_patterns:
                matches = list(re.finditer(pattern, content_before, re.IGNORECASE | re.DOTALL))
                if matches:
                    last_match = matches[-1]
                    scenario_start = search_start + last_match.start()
                    return report_content[scenario_start:placeholder_pos].strip()
            
            # Fallback: return content before placeholder
            return content_before[-2000:].strip()
        
        # Original fallback
        return f"Scenario {scenario_id}: {scenario_title}"
    
    def create_fallback_diagram(self, scenario_id: str, scenario_title: str, product_name: str) -> str:
        """Create a simple fallback diagram"""
        import html
        safe_product_name = html.escape(product_name[:30])
        safe_scenario_id = html.escape(str(scenario_id))
        
        return f"""
        <div class="diagram-container">
            <h3>🎯 Attack Flow - Scenario {safe_scenario_id}</h3>
            <div class="mermaid">
                graph TD
                    A["Target: {safe_product_name}"] --> B["Initial Access"]
                    B --> C["Execution"]
                    C --> D["Persistence"]
                    D --> E["Impact"]
                    
                    classDef default fill:#f9f9f9,stroke:#333,stroke-width:2px
                    classDef critical fill:#ffebee,stroke:#d32f2f,stroke-width:2px
                    classDef start fill:#e8f5e8,stroke:#4caf50,stroke-width:2px
                    
                    class A start
                    class E critical
            </div>
        </div>
        """
    
    async def generate_comprehensive_report(self, all_data: Dict[str, Any]) -> str:
        """Generate complete threat modeling report from all collected data"""
        
        # Determine scenario types based on threat intelligence
        threats = all_data.get('threats', [])
        scenario_types = self.determine_scenario_types(threats)
        
        report_prompt = f"""
        Generate a technical threat modeling report based on the collected threat intelligence data.
        
        THREAT INTELLIGENCE FINDINGS:
        Product: {all_data.get('product_name', 'Unknown')}
        
        17-SOURCE INTELLIGENCE DATA:
        {json.dumps([{
            'cve_id': t.get('cve_id', 'N/A'),
            'title': t.get('title', ''),
            'severity': t.get('severity', ''),
            'cvss_score': t.get('cvss_score', 0),
            'source': t.get('source', ''),
            'description': t.get('description', ''),
            'exploit_available': t.get('exploit_available', False)
        } for t in all_data.get('threats', [])], indent=2)}
        
        THREAT CONTEXT:
        {json.dumps(all_data.get('threat_context', {}), indent=2)}
        
        RISK ASSESSMENT:
        {json.dumps(all_data.get('risks', {}), indent=2)}
        
        Create a threat modeling report with these sections:
        
        1. EXECUTIVE SUMMARY
           - Key vulnerabilities found from threat intelligence
           - Critical risks identified
           - Immediate actions needed
        
        2. THREAT INTELLIGENCE ANALYSIS
           - **Recent Attack Trends:** Based on threat context and intelligence sources
           - **CVE Analysis:** Analysis of specific CVEs found with CVSS scores and exploit status
        
        3. ATTACK SCENARIOS (MAX 3)
           Analyze the threat intelligence findings above and create 3 different attack scenarios.
           Each scenario should be based on actual CVE/vulnerability findings.
           
           For each scenario:
           - Base the attack on specific CVE(s) from the findings
           - Create realistic attack phases based on the vulnerability type
           - Map to appropriate MITRE ATT&CK techniques based on the attack method
           - Include technical details from the threat intelligence
           
           Structure each scenario as:
           **SCENARIO [A/B/C]: [Attack Type based on CVE findings]**
           
           Create attack phases that logically follow from the specific vulnerability:
           - Start with how the CVE would be discovered/exploited
           - Follow the natural progression of the attack
           - Map each phase to relevant MITRE ATT&CK techniques
           - Include timeline, difficulty, and detection ratings
           
           End each scenario with: [DIAGRAM_PLACEHOLDER_SCENARIO_[A/B/C]] 
           
           **For each phase include:**
           - Specific technical implementation details and commands
           - Tools and techniques used in recent real-world attacks
           - Detection signatures, IOCs, and monitoring recommendations
           - Mitigation strategies and security controls
           - References to actual attacks on from latest available intelligence
           - Risk assessment and business impact analysis
        
        4. SECURITY CONTROLS & MITIGATIONS
           Map specific controls to attack steps with implementation details:
           "MFA with hardware tokens mitigates Step 4 credential reuse (Priority: HIGH, Cost: MEDIUM)"
           
           Include for each control:
           - Technical implementation details and configuration requirements
           - Administrative and procedural controls
           - Detection and monitoring capabilities
           - Implementation priority based on threat severity and business impact
           - Cost-benefit analysis and resource requirements
           - Effectiveness rating against identified attack vectors
           - Integration with existing security stack
        
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
        
        report_content = await self.llm.generate(report_prompt, max_tokens=6000)
        
        # Clean up LLM response - remove unwanted content
        report_content = self.clean_llm_response(report_content)
        
        # Ensure proper HTML structure if LLM didn't provide it
        if not report_content.strip().startswith('<'):
            report_content = f"<div class='report-content'>{report_content}</div>"
        
        # Add diagrams after each attack scenario
        threats = all_data.get('threats', [])
        product_name = all_data.get('product_name', 'Unknown Product')
        
        # Parse and generate diagrams for scenarios
        report_content = await self.parse_and_generate_diagrams(report_content, threats, product_name)
        
        diagrams_html = ""
        

        
        return report_content + diagrams_html
    
    def save_html_report(self, report_content: str, product_name: str) -> str:
        """Save report as professional HTML webpage"""
        import html
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_product_name = product_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
        filename = f"{safe_product_name}_ThreatModel_{timestamp}.html"
        
        # Escape product name for HTML title
        escaped_product_name = html.escape(product_name)
        filepath = os.path.join(self.reports_dir, filename)
        
        try:
            html_template = f"""
<!DOCTYPE html>
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