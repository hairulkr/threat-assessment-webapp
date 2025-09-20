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
        """Determine scenario types based on threat intelligence characteristics"""
        scenario_types = []
        
        if not threats:
            return ["SCENARIO A: Generic Attack", "SCENARIO B: System Compromise", "SCENARIO C: Data Breach"]
        
        # Analyze threat characteristics
        has_remote_exploit = any('remote' in t.get('description', '').lower() or 
                               'network' in t.get('description', '').lower() or
                               t.get('cvss_score', 0) >= 7.0 for t in threats)
        
        has_auth_issues = any('authentication' in t.get('description', '').lower() or
                            'authorization' in t.get('description', '').lower() or
                            'privilege' in t.get('description', '').lower() for t in threats)
        
        has_data_exposure = any('disclosure' in t.get('description', '').lower() or
                              'exposure' in t.get('description', '').lower() or
                              'leak' in t.get('description', '').lower() or
                              'injection' in t.get('description', '').lower() for t in threats)
        
        has_dos_issues = any('denial' in t.get('description', '').lower() or
                           'crash' in t.get('description', '').lower() or
                           'availability' in t.get('description', '').lower() for t in threats)
        
        has_supply_chain = any('dependency' in t.get('description', '').lower() or
                             'supply' in t.get('description', '').lower() or
                             'third-party' in t.get('description', '').lower() for t in threats)
        
        # Determine scenario types based on threat analysis
        if has_remote_exploit:
            scenario_types.append("SCENARIO A: Remote Code Execution Attack")
        
        if has_auth_issues:
            scenario_types.append("SCENARIO B: Privilege Escalation Attack")
        elif has_data_exposure:
            scenario_types.append("SCENARIO B: Data Exfiltration Attack")
        
        if has_dos_issues:
            scenario_types.append("SCENARIO C: Availability Attack")
        elif has_supply_chain:
            scenario_types.append("SCENARIO C: Supply Chain Attack")
        elif len(scenario_types) < 2:
            scenario_types.append("SCENARIO C: System Compromise Attack")
        
        # Ensure we have exactly 3 scenarios
        if len(scenario_types) < 3:
            remaining_types = [
                "SCENARIO A: Remote Exploitation",
                "SCENARIO B: Privilege Escalation", 
                "SCENARIO C: Data Breach"
            ]
            for scenario_type in remaining_types:
                if len(scenario_types) >= 3:
                    break
                if not any(scenario_type.split(':')[0] in existing for existing in scenario_types):
                    scenario_types.append(scenario_type)
        
        return scenario_types[:3]
    
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
                
                scenarios_found.append((scenario_id, scenario_title.strip()))
        
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
            
            # Generate diagram
            try:
                async with self.diagram_generator as mcp_gen:
                    diagram_html = await mcp_gen.generate_scenario_diagram(scenario_content, scenario_id, threats, product_name)
            except Exception as e:
                print(f"⚠️ Diagram generation failed for {scenario_id}: {e}")
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
        """Extract the content of a specific scenario"""
        import re
        
        # Find the scenario start
        scenario_patterns = [
            f"SCENARIO\\s+{re.escape(scenario_id)}[^\\n]*",
            f"\\d+\\.\\d+\\s+SCENARIO\\s+{re.escape(scenario_id)}[^\\n]*",
            re.escape(scenario_title)
        ]
        
        start_pos = -1
        for pattern in scenario_patterns:
            match = re.search(pattern, report_content, re.IGNORECASE)
            if match:
                start_pos = match.start()
                break
        
        if start_pos == -1:
            return f"Scenario {scenario_id}: {scenario_title}"
        
        # Find the end (next scenario or section)
        end_patterns = [
            r"SCENARIO\s+[A-Z0-9]",
            r"\d+\.\s+[A-Z]",  # Next numbered section
            r"<h[12]>",  # Next HTML heading
        ]
        
        end_pos = len(report_content)
        for pattern in end_patterns:
            matches = list(re.finditer(pattern, report_content[start_pos + 50:], re.IGNORECASE))
            if matches:
                end_pos = start_pos + 50 + matches[0].start()
                break
        
        return report_content[start_pos:end_pos]
    
    def create_fallback_diagram(self, scenario_id: str, scenario_title: str, product_name: str) -> str:
        """Create a simple fallback diagram"""
        return f"""
        <div class="diagram-container">
            <h3>🎯 Attack Flow - Scenario {scenario_id}</h3>
            <div class="mermaid">
                graph TD
                    A["Target: {product_name[:30]}"] --> B["Initial Access"]
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
        Generate a technical threat modeling report based on the collected data.
        
        THREAT INTELLIGENCE DATA:
        Product: {all_data.get('product_name', 'Unknown')}
        
        SCENARIO TYPES TO GENERATE: {scenario_types}
        
        TOP THREATS (Multi-Agent Ranked):
        {json.dumps([{
            'cve_id': t.get('cve_id', 'N/A'),
            'title': t.get('title', ''),
            'severity': t.get('severity', ''),
            'cvss_score': t.get('cvss_score', 0),
            'source': t.get('source', ''),
            'authority': t.get('authority', ''),
            'ensemble_score': t.get('ensemble_score', 0),
            'description': t.get('description', '')[:200]
        } for t in all_data.get('threats', [])[:8]], indent=2)}
        
        PRODUCT COMPONENTS:
        {json.dumps(all_data.get('product_info', {}).get('components', []), indent=2)}
        
        RISK ANALYSIS:
        {json.dumps(all_data.get('risk_analysis', {}), indent=2)}
        
        
        Create a threat modeling report with these sections:
        
        1. EXECUTIVE SUMMARY
           - Key vulnerabilities found
           - Critical risks identified
           - Immediate actions needed
        
        2. THREAT MODELING & ATTACK ANALYSIS
           Focus on detailed threat modeling methodology with:
           - **Recent Attack Trends:** Latest available attack patterns targeting similar tools and technologies
           - **CVE Analysis:** Detailed vulnerability analysis with CVSS scores and exploit availability
           
           DO NOT include additional subsections - focus only on threat modeling content
        
        3. DETAILED THREAT MODELING SCENARIOS (MAX 3)
           Create exactly 3 different types of comprehensive threat modeling scenarios based on actual threats:
           
           **Determine scenario types based on threat intelligence:**
           - If CRITICAL/HIGH CVE with remote exploit: **SCENARIO A: Remote Code Execution Attack**
           - If authentication/access control issues: **SCENARIO B: Privilege Escalation Attack** 
           - If data exposure/injection vulnerabilities: **SCENARIO C: Data Exfiltration Attack**
           - If denial of service vulnerabilities: **SCENARIO D: Availability Attack**
           - If supply chain/dependency issues: **SCENARIO E: Supply Chain Attack**
           
           **Generate these specific scenario types based on threat analysis: {scenario_types}**
           
           For each scenario type, create a comprehensive attack chain:
           
           **Comprehensive Threat Modeling Analysis:**
           
           **Phase 1: Reconnaissance & Target Identification** (MITRE T1595)
           - Latest reconnaissance campaigns targeting similar tools and platforms
           - Product-specific reconnaissance techniques observed in most recent attacks
           - Attack surface enumeration methods from latest available breach reports
           - Information gathering tactics used in current threat actor campaigns
           - Timeline: 1-7 days | Difficulty: Low | Detection: Medium
           
           **Phase 2: Initial Access & Exploitation** (MITRE T1190/T1566)
           - **Latest Attack Patterns:** Most recent exploitation techniques targeting this technology stack
           - **Current CVE Exploitation:** Vulnerabilities being actively exploited based on latest intelligence
           - **Threat Actor Tools:** Exploit kits and payloads from most recent campaigns against similar platforms
           - **Entry Point Analysis:** Attack vectors observed in latest available breaches of comparable software
           - Timeline: 15 minutes - 2 hours | Difficulty: Medium | Detection: High
           
           **Phase 3: Execution & Persistence** (MITRE T1059/T1053)
           - **Latest Execution Techniques:** Code execution methods from most recent attacks
           - **Current Persistence Tactics:** Mechanisms observed in latest campaigns against similar tools
           - **Modern Evasion Methods:** Anti-detection techniques from most recent threat actor playbooks
           - **Living-off-the-Land:** Latest available LOLBAS techniques targeting this technology stack
           - Timeline: 5-30 minutes | Difficulty: Medium | Detection: Medium
           
           **Phase 4: Privilege Escalation** (MITRE T1068/T1055)
           - Escalation paths specific to the product architecture and deployment model
           - Local privilege escalation techniques relevant to this technology stack
           - Container/service account abuse patterns seen in similar tool compromises
           - Recent privilege escalation techniques used against comparable platforms
           - Timeline: 10 minutes - 2 hours | Difficulty: High | Detection: Medium
           
           **Phase 5: Defense Evasion & Lateral Movement** (MITRE T1070/T1021)
           - Log evasion and artifact cleanup specific to this product type
           - Network propagation techniques leveraging product-specific protocols
           - Credential harvesting methods targeting this technology environment
           - Lateral movement patterns observed in recent attacks on similar tools
           - Timeline: 2-24 hours | Difficulty: High | Detection: Low
           
           **Phase 6: Data Discovery & Collection** (MITRE T1083/T1005)
           - Data location and classification methods for this product type
           - Sensitive information extraction techniques specific to this technology
           - Database and file system access patterns relevant to this platform
           - Recent data collection techniques used against similar tools
           - Timeline: 1-48 hours | Difficulty: Medium | Detection: Medium
           
           **Phase 7: Exfiltration & Impact** (MITRE T1041/T1486)
           - Data exfiltration channels and methods used in recent attacks
           - Business impact assessment based on similar tool compromises
           - Potential for ransomware or destruction based on recent threat actor behavior
           - Real-world impact examples from latest available attacks on comparable platforms
           - Timeline: 30 minutes - 4 hours | Difficulty: Medium | Detection: High
           
           **For each phase include:**
           - Specific technical implementation details and commands
           - Tools and techniques used in recent real-world attacks
           - Detection signatures, IOCs, and monitoring recommendations
           - Mitigation strategies and security controls
           - References to actual attacks on similar tools from latest available intelligence
           - Risk assessment and business impact analysis
           
           End each scenario with: [DIAGRAM_PLACEHOLDER_SCENARIO_X]
        
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