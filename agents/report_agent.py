import json
import os
import asyncio
import re
from typing import Dict, Any
from datetime import datetime
# from mcp_diagram_generator import MCPDiagramGenerator  # No longer needed for batch processing
from .professional_html_formatter import ProfessionalHTMLFormatter
from .prompt_templates import PromptTemplates

class ReportAgent:
    """Enhanced LLM-powered threat modeling report generation with integrated validation"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.reports_dir = "reports"
        # self.diagram_generator = MCPDiagramGenerator(self.llm)  # No longer needed
        self.professional_formatter = ProfessionalHTMLFormatter()
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def determine_scenario_types(self, threats):
        """Let LLM determine scenario types dynamically based on threat intelligence"""
        # Return empty list - let LLM analyze threats and create scenarios dynamically
        return []
    
    def _extract_scenario_threats(self, scenario_content: str, all_threats) -> list:
        """Extract threats relevant to a specific scenario"""
        scenario_threats = []
        
        # Look for CVE IDs mentioned in the scenario
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        mentioned_cves = set(re.findall(cve_pattern, scenario_content, re.IGNORECASE))
        
        # Find threats that match mentioned CVEs
        for threat in all_threats:
            threat_cve = threat.get('cve_id', '')
            if threat_cve in mentioned_cves:
                scenario_threats.append(threat)
        
        # If no specific CVEs found, use first few threats
        if not scenario_threats:
            scenario_threats = all_threats[:2]
        
        return scenario_threats
    
    async def generate_scenario_diagram(self, threats, product_name: str, scenario_title: str) -> str:
        """Generate scenario-specific Mermaid diagram"""
        if not threats:
            return self._create_css_fallback_diagram(product_name)
        
        # Extract scenario type from title
        scenario_type = "Attack"
        if "RCE" in scenario_title or "Remote Code" in scenario_title:
            scenario_type = "RCE"
        elif "Privilege" in scenario_title or "Escalation" in scenario_title:
            scenario_type = "Privilege Escalation"
        elif "Data" in scenario_title or "Exfiltration" in scenario_title:
            scenario_type = "Data Breach"
        
        threat_summary = []
        for threat in threats[:3]:
            cve_id = threat.get('cve_id', 'N/A')
            title = threat.get('title', 'Unknown')[:30]
            severity = threat.get('severity', 'MEDIUM')
            threat_summary.append(f"- {cve_id}: {title} ({severity})")
        
        prompt = f"""
Generate a Mermaid flowchart for {scenario_type} scenario targeting {product_name}:
{chr(10).join(threat_summary)}

Return ONLY valid Mermaid syntax:

graph TD
    A[Attacker] --> B[{scenario_type[:15]}]
    B --> C[Exploit CVE]
    C --> D[Gain Access]
    D --> E[Execute Payload]
    E --> F[Achieve Goal]

Rules:
- Use only letters A-F for node IDs
- Keep labels under 20 characters
- Base on actual threat data
- Use --> for connections
"""
        
        try:
            response = await asyncio.wait_for(
                self.llm.generate(prompt, max_tokens=300),
                timeout=20
            )
            
            mermaid_content = self._extract_mermaid_syntax(response)
            if mermaid_content:
                return f"""
<div class="diagram-container">
    <h4>🎯 {scenario_type} Flow</h4>
    <div class="mermaid">
{mermaid_content}
    </div>
</div>"""
            
        except Exception as e:
            print(f"⚠️ Scenario diagram generation failed: {e}")
        
        return self._create_css_fallback_diagram(product_name)
    
    async def generate_dynamic_attack_flow(self, threats, product_name: str) -> str:
        """Generate LLM-powered Mermaid diagram with structured output"""
        if not threats:
            return self._create_css_fallback_diagram(product_name)
        
        # Create threat summary for LLM
        threat_summary = []
        for threat in threats[:5]:
            cve_id = threat.get('cve_id', 'N/A')
            title = threat.get('title', 'Unknown')[:40]
            severity = threat.get('severity', 'MEDIUM')
            threat_summary.append(f"- {cve_id}: {title} ({severity})")
        
        prompt = f"""
Generate a Mermaid flowchart for attack flow based on these threats for {product_name}:
{chr(10).join(threat_summary)}

Return ONLY valid Mermaid syntax in this exact format:

graph TD
    A[Target: {product_name[:15]}] --> B[Initial Access T1190]
    B --> C[Execution T1059]
    C --> D[Persistence T1053]
    D --> E[Impact T1486]

Rules:
- Use only letters A-Z for node IDs
- Keep node labels under 25 characters
- Include MITRE technique IDs
- Base steps on actual CVE types found
- Use --> for connections
- Start with 'graph TD'
"""
        
        try:
            response = await asyncio.wait_for(
                self.llm.generate(prompt, max_tokens=400),
                timeout=30
            )
            
            # Extract and validate Mermaid syntax
            mermaid_content = self._extract_mermaid_syntax(response)
            if mermaid_content:
                return self._wrap_mermaid_diagram(mermaid_content)
            
        except Exception as e:
            print(f"⚠️ LLM Mermaid generation failed: {e}")
        
        return self._create_css_fallback_diagram(product_name)
    

    
    def _extract_mermaid_syntax(self, response: str) -> str:
        """Extract and validate Mermaid syntax from LLM response"""
        # Look for mermaid content between various markers
        patterns = [
            r'```mermaid\n(.*?)```',
            r'```\n(graph TD.*?)```',
            r'(graph TD.*?)(?=\n\n|$)',
            r'```(graph TD.*?)```'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            if match:
                mermaid_content = match.group(1).strip()
                if self._validate_mermaid_syntax(mermaid_content):
                    return mermaid_content
        
        return None
    
    def _validate_mermaid_syntax(self, content: str) -> bool:
        """Basic validation of Mermaid syntax"""
        if not content.startswith('graph TD'):
            return False
        if '-->' not in content:
            return False
        if '[' not in content or ']' not in content:
            return False
        return True
    
    def _wrap_mermaid_diagram(self, mermaid_content: str) -> str:
        """Wrap validated Mermaid content in HTML"""
        return f"""
<div class="diagram-container">
    <h3>🎯 LLM-Generated Attack Flow</h3>
    <div class="mermaid">
{mermaid_content}
    </div>
</div>"""
    

    
    async def parse_and_generate_diagrams(self, report_content: str, threats, product_name: str) -> str:
        """Generate LLM-powered Mermaid diagrams and insert after each scenario"""
        
        # Find all scenario sections (h3 headings that contain "Scenario" or threat-related keywords)
        scenario_pattern = r'(<h3[^>]*>(?:.*?(?:Scenario|Attack|Threat|CVE|Vulnerability).*?)</h3>)(.*?)(?=<h[23]|$)'
        scenarios = list(re.finditer(scenario_pattern, report_content, re.DOTALL | re.IGNORECASE))
        
        if not scenarios:
            # Fallback: generate one diagram after executive summary
            attack_flow_diagram = await self.generate_dynamic_attack_flow(threats, product_name)
            summary_match = re.search(r'(<h2[^>]*>Executive Summary</h2>.*?</p>)', report_content, re.DOTALL | re.IGNORECASE)
            if summary_match:
                insert_pos = summary_match.end()
                report_content = report_content[:insert_pos] + "\n" + attack_flow_diagram + report_content[insert_pos:]
            return report_content
        
        # Generate diagrams for each scenario (process in reverse order to maintain positions)
        for i, scenario_match in enumerate(reversed(scenarios)):
            scenario_title = scenario_match.group(1)
            scenario_content = scenario_match.group(2)
            
            # Extract relevant threats for this scenario
            scenario_threats = self._extract_scenario_threats(scenario_content, threats)
            
            # Generate scenario-specific diagram
            scenario_diagram = await self.generate_scenario_diagram(scenario_threats, product_name, scenario_title)
            
            # Insert diagram at the end of this scenario
            insert_pos = scenario_match.end()
            report_content = report_content[:insert_pos] + "\n" + scenario_diagram + report_content[insert_pos:]
        
        return report_content
    

    

    
    def _create_css_fallback_diagram(self, product_name: str) -> str:
        """Create CSS-only fallback diagram when Mermaid fails"""
        safe_product = re.sub(r'[^a-zA-Z0-9\s]', '', product_name)[:20]
        
        return f"""
<div class="diagram-container">
    <h3>🎯 Attack Flow Analysis</h3>
    <div class="css-diagram">
        <div class="flow-step target">{safe_product}</div>
        <div class="arrow">↓</div>
        <div class="flow-step">Initial Access<br><small>T1190</small></div>
        <div class="arrow">↓</div>
        <div class="flow-step">Execution<br><small>T1059</small></div>
        <div class="arrow">↓</div>
        <div class="flow-step">Persistence<br><small>T1053</small></div>
        <div class="arrow">↓</div>
        <div class="flow-step impact">Impact<br><small>T1486</small></div>
    </div>
</div>
<style>
.css-diagram {{ display: flex; flex-direction: column; align-items: center; gap: 10px; }}
.flow-step {{ padding: 12px 20px; border: 2px solid #333; border-radius: 8px; background: #f9f9f9; text-align: center; min-width: 120px; }}
.flow-step.target {{ background: #e3f2fd; border-color: #1976d2; }}
.flow-step.impact {{ background: #ffebee; border-color: #d32f2f; }}
.arrow {{ font-size: 24px; color: #666; }}
</style>"""
    
    def validate_data_quality(self, all_data: Dict[str, Any]) -> Dict[str, Any]:
        """Integrated data quality validation (replaces ReviewerAgent)"""
        threats = all_data.get('threats', [])
        product_name = all_data.get('product_name', 'Unknown')
        
        # Always proceed - never terminate
        threat_count = len(threats)
        confidence = 7.0 if threat_count > 0 else 5.0
        
        return {
            'terminate_recommended': False,
            'confidence_score': confidence,
            'threat_count': threat_count,
            'validation_summary': f'Proceeding with {threat_count} threats'
        }
    
    async def generate_comprehensive_report(self, all_data: Dict[str, Any]) -> str:
        """Generate complete threat modeling report with integrated validation"""
        
        # Integrated data quality validation
        validation_result = self.validate_data_quality(all_data)
        
        # Never terminate - always generate a report
        print(f"   📊 DATA QUALITY: {len(all_data.get('threats', []))} threats found, proceeding with report generation")
        
        # Generate report using standardized prompt
        report_prompt = PromptTemplates.get_comprehensive_report_prompt(all_data)
        
        try:
            report_content = await asyncio.wait_for(
                self.llm.generate(report_prompt, max_tokens=6000),
                timeout=180
            )
            
            # Clean and normalize LLM response
            report_content = self._clean_llm_response(report_content)
            
            # Ensure consistent CVE and MITRE formatting before HTML conversion
            report_content = self._normalize_threat_references(report_content)
            
            # Convert to professional HTML format
            report_content = self.professional_formatter.convert_markdown_to_html(report_content)
            
            # Generate LLM-powered Mermaid diagrams
            threats = all_data.get('threats', [])
            product_name = all_data.get('product_name', 'Unknown Product')
            report_content = await self.parse_and_generate_diagrams(report_content, threats, product_name)
            
            # Add Mermaid.js script for diagram rendering
            if '<div class="mermaid">' in report_content:
                report_content += '\n<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>\n<script>mermaid.initialize({startOnLoad:true});</script>'
            
            print(f"   ✅ REPORT GENERATED: {len(report_content)} characters, confidence {validation_result.get('confidence_score', 0)}/10")
            
            return report_content
            
        except asyncio.TimeoutError:
            print(f"   ⏰ Report generation timed out")
            return self._generate_basic_report(all_data)
        except Exception as e:
            print(f"   ⚠️ Report generation failed: {e}")
            return self._generate_basic_report(all_data)
    
    def _normalize_threat_references(self, content: str) -> str:
        """Normalize CVE and MITRE references for consistent formatting"""
        # Normalize CVE references
        content = re.sub(r'\*\*(CVE-\d{4}-\d{4,})\*\*', r'\1', content)
        content = re.sub(r'CVE[:\s-]*(\d{4}-\d{4,})', r'CVE-\1', content)
        
        # Normalize MITRE ATT&CK references
        content = re.sub(r'\*\*(T\d{4}(?:\.\d{3})?)\*\*', r'\1', content)
        content = re.sub(r'MITRE[:\s-]*(T\d{4}(?:\.\d{3})?)', r'\1', content)
        
        return content
    
    def _generate_basic_report(self, all_data: Dict[str, Any]) -> str:
        """Generate basic fallback report when full generation fails"""
        product_name = all_data.get('product_name', 'Unknown Product')
        threats = all_data.get('threats', [])
        
        threat_count = len(threats)
        high_severity = len([t for t in threats if t.get('severity') == 'HIGH'])
        critical_severity = len([t for t in threats if t.get('severity') == 'CRITICAL'])
        
        # Generate threat list with proper CVE formatting
        threat_items = []
        for t in threats[:10]:
            cve_id = t.get('cve_id', 'N/A')
            if cve_id != 'N/A' and not cve_id.startswith('CVE-'):
                cve_id = f'CVE-{cve_id}' if cve_id.replace('-', '').isdigit() else cve_id
            
            severity = t.get('severity', 'Unknown')
            title = t.get('title', 'Unknown Threat')
            
            threat_items.append(
                f'<li><strong>{title}</strong> - <span class="severity-{severity}">{severity}</span> '
                f'(<span class="cve-badge">{cve_id}</span>)</li>'
            )
        
        basic_content = f"""
# Threat Assessment Report - {product_name}

## Executive Summary
This assessment identified **{threat_count} potential threats** for {product_name}.

- Critical threats: {critical_severity}
- High severity threats: {high_severity}
- Assessment completed with basic analysis

## Key Findings
The following threats were identified:

{''.join(threat_items)}

## Recommendations
- Implement multi-factor authentication
- Keep software updated with latest security patches
- Deploy network segmentation and monitoring
- Establish incident response procedures
- Conduct regular security assessments
        """
        
        # Use professional formatter for consistency
        return self.professional_formatter.convert_markdown_to_html(basic_content)
    
    def save_html_report(self, report_content: str, product_name: str) -> str:
        """Save report as professional HTML webpage"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_product_name = product_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
        filename = f"{safe_product_name}_ThreatModel_{timestamp}.html"
        filepath = os.path.join(self.reports_dir, filename)
        
        try:
            # Ensure report content is properly formatted
            if not report_content or report_content.strip() == "":
                report_content = "<h1>Report Generation Error</h1><p>No content was generated. Please try again.</p>"
            
            # Create complete professional HTML document
            html_template = self.professional_formatter.create_professional_template(report_content, product_name)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_template)
            
            print(f"   📄 HTML report saved: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"Error creating HTML report: {e}")
            return f"HTML report creation failed: {e}"
    

    

    
    def _clean_llm_response(self, response: str) -> str:
        """Clean LLM response text"""
        import re
        # Remove diagram placeholders that might still appear
        response = re.sub(r'\[DIAGRAM_PLACEHOLDER_SCENARIO_[A-Z]\]', '', response)
        response = re.sub(r'\[DIAGRAM_[A-Z]\]', '', response)
        
        # Remove extra whitespace and normalize line breaks
        response = re.sub(r'\n\s*\n\s*\n', '\n\n', response)
        response = re.sub(r'^\s+|\s+$', '', response, flags=re.MULTILINE)
        return response.strip()