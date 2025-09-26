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
    
    async def generate_batch_diagrams(self, scenarios_found: list, threats, product_name: str) -> Dict[str, str]:
        """Generate all scenario diagrams in a single batch LLM call"""
        if not scenarios_found:
            return {}
        
        print(f"🎯 Batch generating diagrams for {len(scenarios_found)} scenarios")
        
        # Prepare batch prompt for all scenarios
        scenario_texts = []
        for scenario_id, scenario_title in scenarios_found:
            scenario_content = f"Scenario {scenario_id}: {scenario_title}"
            scenario_texts.append(f"SCENARIO {scenario_id}: {scenario_title}\n{scenario_content[:500]}")
        
        batch_prompt = f"""
        Analyze these attack scenarios for {product_name} and extract attack phases for each:
        
        {chr(10).join(scenario_texts)}
        
        For each scenario, return attack phases with MITRE technique IDs:
        
        SCENARIO A PHASES:
        1. [Attack Phase Name] - [T1234]
        2. [Attack Phase Name] - [T1234]
        
        SCENARIO B PHASES:
        1. [Attack Phase Name] - [T1234]
        2. [Attack Phase Name] - [T1234]
        
        SCENARIO C PHASES:
        1. [Attack Phase Name] - [T1234]
        2. [Attack Phase Name] - [T1234]
        
        Focus on realistic attack progression based on the threat intelligence provided.
        """
        
        try:
            response = await asyncio.wait_for(
                self.llm.generate(batch_prompt, max_tokens=1000),
                timeout=60
            )
            
            # Parse batch response and generate diagrams
            diagrams = {}
            for scenario_id, scenario_title in scenarios_found:
                phases = self._extract_phases_from_batch_response(response, scenario_id)
                if not phases:
                    # Try extracting phases directly from scenario content
                    scenario_content = f"Scenario {scenario_id}: {scenario_title}"
                    phases = self._extract_phases_from_content(scenario_content)
                
                if phases:
                    diagram_html = self._generate_diagram_from_phases(phases, scenario_id, product_name)
                    diagrams[scenario_id] = diagram_html
                    print(f"✅ Batch diagram generated for Scenario {scenario_id} with {len(phases)} phases")
                else:
                    diagrams[scenario_id] = self.create_fallback_diagram(scenario_id, scenario_title, product_name, threats)
                    print(f"🔄 Using intel-based fallback diagram for Scenario {scenario_id}")
            
            return diagrams
            
        except Exception as e:
            print(f"⚠️ Batch diagram generation failed: {e}")
            # Fallback to individual diagrams for each scenario
            diagrams = {}
            for scenario_id, scenario_title in scenarios_found:
                diagrams[scenario_id] = self.create_fallback_diagram(scenario_id, scenario_title, product_name, threats)
            return diagrams
    
    def _extract_phases_from_batch_response(self, response: str, scenario_id: str) -> list:
        """Extract attack phases for specific scenario from batch response"""
        import re
        
        # Find scenario section in response
        pattern = rf'SCENARIO\s+{scenario_id}\s+PHASES?:(.*?)(?=SCENARIO\s+[A-Z]|$)'
        match = re.search(pattern, response, re.IGNORECASE | re.DOTALL)
        
        if not match:
            return []
        
        scenario_text = match.group(1)
        phases = []
        
        # Extract numbered phases - improved pattern to handle various formats
        phase_patterns = [
            r'\d+\.\s*([^-\n]+)\s*-\s*(T\d{4}(?:\.\d{3})?)',  # "1. Phase Name - T1234"
            r'Phase\s+(\d+):\s*([^\n]+)',  # "Phase 1: Phase Name"
            r'(\d+)\s*[.:]\s*([^\n-]+?)(?:\s*-\s*(T\d{4}(?:\.\d{3})?))?',  # "1. Phase Name" or "1: Phase Name - T1234"
        ]
        
        for pattern in phase_patterns:
            for match in re.finditer(pattern, scenario_text):
                if len(match.groups()) == 2:  # Phase X: Name format
                    phase_name = match.group(2).strip()[:40]
                    mitre_id = 'T1059'  # Default MITRE technique
                elif len(match.groups()) >= 3:  # Other formats
                    phase_name = match.group(2).strip()[:40] if match.group(2) else match.group(1).strip()[:40]
                    mitre_id = match.group(3) if len(match.groups()) >= 3 and match.group(3) else 'T1059'
                else:
                    continue
                
                if phase_name and phase_name not in [p[0] for p in phases]:
                    phases.append((phase_name, mitre_id))
        
        return phases[:6]  # Limit to 6 phases
    
    def _generate_diagram_from_phases(self, phases: list, scenario_id: str, product_name: str) -> str:
        """Generate mermaid diagram from extracted phases"""
        if not phases:
            return self.create_fallback_diagram(scenario_id, "Unknown", product_name, None)
        
        # Build clean mermaid diagram
        mermaid_lines = ["graph TD"]
        mermaid_lines.append(f"    A[{product_name[:20]}]")
        
        for i, (phase_desc, mitre_id) in enumerate(phases, 1):
            node_id = chr(65 + i)  # B, C, D, E...
            clean_desc = phase_desc[:25].replace('"', '').replace('[', '').replace(']', '')
            clean_mitre = mitre_id[:10]
            
            mermaid_lines.append(f"    {node_id}[{clean_desc} {clean_mitre}]")
            
            if i == 1:
                mermaid_lines.append(f"    A --> {node_id}")
            else:
                prev_node = chr(65 + i - 1)
                mermaid_lines.append(f"    {prev_node} --> {node_id}")
        
        mermaid = "\n".join(mermaid_lines)
        
        return f"""
<div class="diagram-container">
    <h3>Attack Flow - Scenario {scenario_id}</h3>
    <div class="mermaid">
{mermaid}
    </div>
</div>"""
    
    def _extract_phases_from_content(self, content: str) -> list:
        """Extract phases directly from scenario content for diagram generation"""
        phases = []
        
        # Simple phase extraction - look for "Phase X:" patterns
        phase_matches = re.finditer(r'Phase\s+(\d+):\s*([^\n]+)', content, re.IGNORECASE)
        
        for match in phase_matches:
            phase_num = int(match.group(1))
            phase_desc = match.group(2).strip()[:40]
            
            # Extract MITRE technique if present in description
            mitre_match = re.search(r'(T\d{4}(?:\.\d{3})?)', phase_desc)
            mitre_id = mitre_match.group(1) if mitre_match else f'T{1190 + phase_num}'
            
            phases.append((phase_desc, mitre_id))
        
        return phases[:6]  # Limit to 6 phases
    
    async def parse_and_generate_diagrams(self, report_content: str, threats, product_name: str) -> str:
        """Parse scenarios and generate diagrams using batch processing"""
        # Find unique scenarios using simple regex
        scenarios_found = self._find_scenarios_simple(report_content)
        
        # If no scenarios found, try to extract attack flow from content
        if not scenarios_found:
            attack_flow_diagram = self._generate_attack_flow_from_content(report_content, product_name, threats)
            if attack_flow_diagram:
                # Insert diagram after first heading
                heading_match = re.search(r'<h[1-3][^>]*>.*?</h[1-3]>', report_content)
                if heading_match:
                    insert_pos = heading_match.end()
                    report_content = report_content[:insert_pos] + "\n" + attack_flow_diagram + report_content[insert_pos:]
            return report_content
        
        # Generate all diagrams in batch
        diagrams = await self.generate_batch_diagrams(scenarios_found, threats, product_name)
        
        # Replace placeholders with generated diagrams
        for scenario_id, diagram_html in diagrams.items():
            report_content = self._replace_placeholders_simple(report_content, scenario_id, diagram_html)
        
        return report_content
    
    def _extract_techniques_from_threats(self, threats) -> list:
        """Extract MITRE techniques from threat intelligence dynamically"""
        techniques = []
        
        for threat in threats[:4]:  # Limit to 4 threats
            cve_id = threat.get('cve_id', '')
            title = threat.get('title', '').lower()
            description = threat.get('description', '').lower()
            
            # Map threat characteristics to MITRE techniques
            if 'remote code execution' in title or 'rce' in title:
                techniques.append(('Remote Code Execution', 'T1190', 'Exploit Public-Facing Application'))
            elif 'privilege escalation' in title or 'elevation' in title:
                techniques.append(('Privilege Escalation', 'T1068', 'Exploitation for Privilege Escalation'))
            elif 'buffer overflow' in title or 'memory corruption' in title:
                techniques.append(('Memory Corruption', 'T1055', 'Process Injection'))
            elif 'authentication' in title or 'bypass' in title:
                techniques.append(('Credential Access', 'T1110', 'Brute Force'))
            elif 'denial of service' in title or 'dos' in title:
                techniques.append(('Impact', 'T1499', 'Endpoint Denial of Service'))
            elif 'information disclosure' in title or 'leak' in title:
                techniques.append(('Collection', 'T1005', 'Data from Local System'))
            else:
                # Default based on severity
                severity = threat.get('severity', 'MEDIUM')
                if severity in ['CRITICAL', 'HIGH']:
                    techniques.append(('Initial Access', 'T1190', 'Exploit Public-Facing Application'))
                else:
                    techniques.append(('Execution', 'T1059', 'Command and Scripting Interpreter'))
        
        # Ensure we have at least 4 phases
        if len(techniques) < 4:
            default_phases = [
                ('Initial Access', 'T1190', 'Exploit Public-Facing Application'),
                ('Execution', 'T1059.003', 'Windows Command Shell'),
                ('Persistence', 'T1053.005', 'Scheduled Task'),
                ('Impact', 'T1486', 'Data Encrypted for Impact')
            ]
            techniques.extend(default_phases[len(techniques):4])
        
        return techniques[:4]
    
    def _generate_attack_flow_from_content(self, content: str, product_name: str, threats=None) -> str:
        """Generate attack flow diagram from content that mentions attack phases"""
        import html
        
        # Look for CVEs and create attack flow based on them
        cve_pattern = r'(CVE-\d{4}-\d{4,})[^\n]*([^\n]{50,100})'
        cve_matches = re.finditer(cve_pattern, content, re.IGNORECASE)
        
        phases = []
        mitre_techniques = re.findall(r'T\d{4}(?:\.\d{3})?', content)
        
        # Predefined realistic attack techniques
        default_techniques = [
            ('Initial Access', 'T1190'),
            ('Execution', 'T1059.003'),
            ('Privilege Escalation', 'T1068'),
            ('Impact', 'T1486')
        ]
        
        # Extract attack phases from CVE descriptions
        for i, match in enumerate(cve_matches):
            if i >= 4:  # Limit to 4 CVEs
                break
            cve_id = match.group(1)
            description = match.group(2).strip()[:40]
            mitre_id = mitre_techniques[i] if i < len(mitre_techniques) else default_techniques[i % len(default_techniques)][1]
            
            # Map CVE to attack phase with realistic techniques
            if 'remote code execution' in description.lower() or 'rce' in description.lower():
                phase_name = 'Remote Code Execution'
                mitre_id = 'T1190'
            elif 'privilege' in description.lower():
                phase_name = 'Privilege Escalation'
                mitre_id = 'T1068'
            elif 'buffer overflow' in description.lower():
                phase_name = 'Memory Corruption'
                mitre_id = 'T1055'
            elif 'authentication' in description.lower():
                phase_name = 'Credential Access'
                mitre_id = 'T1110'
            else:
                phase_name = default_techniques[i % len(default_techniques)][0]
                mitre_id = default_techniques[i % len(default_techniques)][1]
            
            phases.append((phase_name, cve_id, mitre_id))
        
        # If no CVEs found, use realistic attack phases
        if not phases:
            phases = [
                ('Initial Access', 'T1190 - Exploit Public-Facing Application', 'T1190'),
                ('Execution', 'T1059.003 - Windows Command Shell', 'T1059.003'),
                ('Persistence', 'T1053.005 - Scheduled Task', 'T1053.005'),
                ('Impact', 'T1486 - Data Encrypted for Impact', 'T1486')
            ]
        
        if not phases:
            return ""
        
        # Generate mermaid diagram
        safe_product_name = html.escape(product_name[:25])
        mermaid = f"graph TD\n    Target[\"🎯 {safe_product_name}\"]\n"
        
        for i, (phase_name, desc, mitre_id) in enumerate(phases[:4], 1):
            node_id = f"Phase{i}"
            clean_phase = html.escape(phase_name[:15])
            clean_mitre = html.escape(mitre_id)
            
            mermaid += f"    {node_id}[\"{clean_phase}\\n{clean_mitre}\"]\n"
            
            if i == 1:
                mermaid += f"    Target --> {node_id}\n"
            else:
                prev_node = f"Phase{i-1}"
                mermaid += f"    {prev_node} --> {node_id}\n"
        
        mermaid += """\n    classDef default fill:#f9f9f9,stroke:#333,stroke-width:2px
    classDef critical fill:#ffebee,stroke:#d32f2f,stroke-width:2px
    classDef target fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    
    class Target target"""
        
        return f"""
<div class="diagram-container">
    <h3>🎯 Attack Flow Analysis</h3>
    <div class="mermaid" id="diagram-attack-flow">
        {mermaid}
    </div>
</div>"""
    
    def create_fallback_diagram(self, scenario_id: str, scenario_title: str, product_name: str, threats=None) -> str:
        """Create dynamic fallback diagram based on threat intelligence"""
        import html
        safe_product_name = html.escape(product_name[:30])
        safe_scenario_id = html.escape(str(scenario_id))
        
        # Extract techniques from threat intelligence if available
        if threats:
            flow = self._extract_techniques_from_threats(threats)
        else:
            # Only use static flow as last resort
            flow = [
                ('Initial Access', 'T1190', 'Exploit Public-Facing Application'),
                ('Execution', 'T1059.003', 'Windows Command Shell'),
                ('Persistence', 'T1053.005', 'Scheduled Task'),
                ('Impact', 'T1486', 'Data Encrypted for Impact')
            ]
        
        # Build mermaid diagram
        mermaid = f"graph TD\n    Target[\"🎯 {safe_product_name}\"]\n"
        
        for i, (phase, technique, description) in enumerate(flow, 1):
            node_id = f"Phase{i}"
            mermaid += f"    {node_id}[\"{phase}\\n{technique}\\n{description[:20]}...\"]\n"
            
            if i == 1:
                mermaid += f"    Target --> {node_id}\n"
            else:
                prev_node = f"Phase{i-1}"
                mermaid += f"    {prev_node} --> {node_id}\n"
        
        mermaid += """\n    classDef default fill:#f9f9f9,stroke:#333,stroke-width:2px
    classDef critical fill:#ffebee,stroke:#d32f2f,stroke-width:2px
    classDef target fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    
    class Target target
    class Phase4 critical"""
        
        return f"""
<div class="diagram-container">
    <h3>🎯 Attack Flow - Scenario {safe_scenario_id}</h3>
    <div class="mermaid" id="diagram-{safe_scenario_id}">
        {mermaid}
    </div>
</div>"""
    
    def validate_data_quality(self, all_data: Dict[str, Any]) -> Dict[str, Any]:
        """Integrated data quality validation (replaces ReviewerAgent)"""
        threats = all_data.get('threats', [])
        product_name = all_data.get('product_name', 'Unknown')
        
        # Simple, reliable validation criteria
        if len(threats) == 0:
            return {
                'terminate_recommended': True,
                'reason': 'No threat intelligence found',
                'confidence_score': 0.0
            }
        
        # Calculate confidence based on threat count and sources
        threat_sources = set(t.get('source', 'Unknown') for t in threats)
        nvd_threats = len([t for t in threats if t.get('source') == 'NVD'])
        
        if len(threats) >= 5 and len(threat_sources) >= 3:
            confidence = 9.0
        elif len(threats) >= 3 and nvd_threats > 0:
            confidence = 8.0
        elif len(threats) >= 1:
            confidence = 7.0
        else:
            confidence = 3.0
        
        print(f"   📊 DATA QUALITY: {len(threats)} threats, {len(threat_sources)} sources, confidence {confidence}/10")
        
        return {
            'terminate_recommended': False,
            'confidence_score': confidence,
            'threat_count': len(threats),
            'source_diversity': len(threat_sources),
            'validation_summary': f'Found {len(threats)} threats from {len(threat_sources)} sources'
        }
    
    async def generate_comprehensive_report(self, all_data: Dict[str, Any]) -> str:
        """Generate complete threat modeling report with integrated validation"""
        
        # Integrated data quality validation
        validation_result = self.validate_data_quality(all_data)
        
        if validation_result.get('terminate_recommended', False):
            print(f"   ⚠️ ANALYSIS TERMINATED: {validation_result.get('reason')}")
            return None
        
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
    
    def _find_scenarios_simple(self, content: str) -> list:
        """Simple scenario finder using regex"""
        import re
        scenarios = []
        # Look for scenario patterns
        scenario_matches = re.finditer(r'scenario\s+([a-z])\s*[:.]?\s*([^\n]+)', content, re.IGNORECASE)
        for match in scenario_matches:
            scenario_id = match.group(1).upper()
            scenario_title = match.group(2).strip()
            scenarios.append((scenario_id, scenario_title))
        return scenarios[:3]  # Limit to 3 scenarios
    
    def _replace_placeholders_simple(self, content: str, scenario_id: str, diagram_html: str) -> str:
        """Simple placeholder replacement"""
        placeholder = f"[DIAGRAM_{scenario_id}]"
        return content.replace(placeholder, diagram_html)
    
    def _clean_llm_response(self, response: str) -> str:
        """Clean LLM response text"""
        import re
        # Remove extra whitespace and normalize line breaks
        response = re.sub(r'\n\s*\n\s*\n', '\n\n', response)
        response = re.sub(r'^\s+|\s+$', '', response, flags=re.MULTILINE)
        return response.strip()