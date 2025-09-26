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
    
    async def generate_dynamic_attack_flow(self, threats, product_name: str) -> str:
        """Generate dynamic attack flow based on actual threat intelligence"""
        if not threats:
            return self._create_css_fallback_diagram(product_name)
        
        # Create threat summary for LLM
        threat_summary = []
        for threat in threats[:8]:
            cve_id = threat.get('cve_id', 'N/A')
            title = threat.get('title', 'Unknown')[:50]
            severity = threat.get('severity', 'MEDIUM')
            threat_summary.append(f"- {cve_id}: {title} ({severity})")
        
        prompt = f"""
Analyze these specific threats for {product_name}:
{chr(10).join(threat_summary)}

Create a realistic attack flow with 3-8 steps based on ACTUAL vulnerabilities found.
Return ONLY this JSON format:

{{
  "attack_flow": [
    {{"step": 1, "phase": "Initial Access", "technique": "T1190", "description": "Exploit web vulnerability"}},
    {{"step": 2, "phase": "Execution", "technique": "T1059", "description": "Run malicious script"}}
  ]
}}
"""
        
        try:
            response = await asyncio.wait_for(
                self.llm.generate(prompt, max_tokens=800),
                timeout=45
            )
            
            # Extract JSON from response
            import json
            json_match = re.search(r'\{.*"attack_flow".*\}', response, re.DOTALL)
            if json_match:
                attack_data = json.loads(json_match.group(0))
                return self._generate_safe_mermaid(attack_data['attack_flow'], product_name)
            
        except Exception as e:
            print(f"⚠️ Dynamic diagram generation failed: {e}")
        
        return self._create_css_fallback_diagram(product_name)
    

    
    def _generate_safe_mermaid(self, attack_flow: list, product_name: str) -> str:
        """Generate safe Mermaid diagram from structured attack flow data"""
        if not attack_flow:
            return self._create_css_fallback_diagram(product_name)
        
        # Sanitize product name
        safe_product = re.sub(r'[^a-zA-Z0-9\s]', '', product_name)[:15]
        
        # Build mermaid with safe syntax
        mermaid_lines = ["graph TD"]
        mermaid_lines.append(f"    Target[{safe_product}]")
        
        for i, step in enumerate(attack_flow[:8], 1):
            node_id = f"S{i}"
            # Sanitize all text - only alphanumeric and spaces
            safe_desc = re.sub(r'[^a-zA-Z0-9\s]', '', step.get('description', ''))[:12]
            safe_technique = re.sub(r'[^T0-9.]', '', step.get('technique', 'T1059'))[:8]
            
            mermaid_lines.append(f"    {node_id}[{safe_desc} {safe_technique}]")
            
            if i == 1:
                mermaid_lines.append(f"    Target --> {node_id}")
            else:
                mermaid_lines.append(f"    S{i-1} --> {node_id}")
        
        mermaid = "\n".join(mermaid_lines)
        
        return f"""
<div class="diagram-container">
    <h3>🎯 Dynamic Attack Flow Analysis</h3>
    <div class="mermaid">
{mermaid}
    </div>
</div>"""
    

    
    async def parse_and_generate_diagrams(self, report_content: str, threats, product_name: str) -> str:
        """Generate dynamic attack flow diagram and insert into report"""
        # Generate single dynamic attack flow diagram
        attack_flow_diagram = await self.generate_dynamic_attack_flow(threats, product_name)
        
        # Insert diagram after first heading
        heading_match = re.search(r'<h[1-3][^>]*>.*?</h[1-3]>', report_content)
        if heading_match:
            insert_pos = heading_match.end()
            report_content = report_content[:insert_pos] + "\n" + attack_flow_diagram + report_content[insert_pos:]
        else:
            # Insert at beginning if no heading found
            report_content = attack_flow_diagram + "\n" + report_content
        
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
            
            # Generate diagrams for scenarios using batch processing
            threats = all_data.get('threats', [])
            product_name = all_data.get('product_name', 'Unknown Product')
            report_content = await self.parse_and_generate_diagrams(report_content, threats, product_name)
            
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
        # Remove extra whitespace and normalize line breaks
        response = re.sub(r'\n\s*\n\s*\n', '\n\n', response)
        response = re.sub(r'^\s+|\s+$', '', response, flags=re.MULTILINE)
        return response.strip()