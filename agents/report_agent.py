import json
import os
import asyncio
from typing import Dict, Any
from datetime import datetime
# from mcp_diagram_generator import MCPDiagramGenerator  # No longer needed for batch processing
from .report_formatter import ReportFormatter
from .professional_html_formatter import ProfessionalHTMLFormatter
from .scenario_parser import ScenarioParser
from .prompt_templates import PromptTemplates

class ReportAgent:
    """Enhanced LLM-powered threat modeling report generation with integrated validation"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.reports_dir = "reports"
        # self.diagram_generator = MCPDiagramGenerator(self.llm)  # No longer needed
        self.formatter = ReportFormatter()
        self.professional_formatter = ProfessionalHTMLFormatter()
        self.scenario_parser = ScenarioParser()
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
            scenario_content = self.scenario_parser.extract_scenario_content(
                "", scenario_id, scenario_title  # Will use fallback content
            )
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
                if phases:
                    diagram_html = self._generate_diagram_from_phases(phases, scenario_id, product_name)
                    diagrams[scenario_id] = diagram_html
                    print(f"✅ Batch diagram generated for Scenario {scenario_id}")
                else:
                    diagrams[scenario_id] = self.create_fallback_diagram(scenario_id, scenario_title, product_name)
                    print(f"🔄 Using fallback diagram for Scenario {scenario_id}")
            
            return diagrams
            
        except Exception as e:
            print(f"⚠️ Batch diagram generation failed: {e}")
            # Fallback to individual diagrams for each scenario
            diagrams = {}
            for scenario_id, scenario_title in scenarios_found:
                diagrams[scenario_id] = self.create_fallback_diagram(scenario_id, scenario_title, product_name)
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
        
        # Extract numbered phases
        phase_pattern = r'\d+\.\s*([^-\n]+)\s*-\s*(T\d{4}(?:\.\d{3})?)?'
        for match in re.finditer(phase_pattern, scenario_text):
            phase_name = match.group(1).strip()[:40]
            mitre_id = match.group(2) if match.group(2) else 'T1059'
            if phase_name:
                phases.append((phase_name, mitre_id))
        
        return phases[:6]  # Limit to 6 phases
    
    def _generate_diagram_from_phases(self, phases: list, scenario_id: str, product_name: str) -> str:
        """Generate mermaid diagram from extracted phases"""
        import html
        safe_product_name = html.escape(product_name[:25])
        safe_scenario_id = html.escape(str(scenario_id))
        
        if not phases:
            return self.create_fallback_diagram(scenario_id, "Unknown", product_name)
        
        # Build mermaid diagram
        mermaid = f"graph TD\n    Target[\"🎯 {safe_product_name}\"]\n"
        
        for i, (phase_desc, mitre_id) in enumerate(phases, 1):
            phase_name = f"Phase{i}"
            clean_desc = html.escape(phase_desc[:30])
            clean_mitre = html.escape(mitre_id)
            
            mermaid += f"    {phase_name}[\"{clean_desc}\\n{clean_mitre}\"]\n"
            
            if i == 1:
                mermaid += f"    Target --> {phase_name}\n"
            else:
                prev_phase = f"Phase{i-1}"
                mermaid += f"    {prev_phase} --> {phase_name}\n"
        
        # Add styling
        mermaid += """\n    classDef default fill:#f9f9f9,stroke:#333,stroke-width:2px
    classDef critical fill:#ffebee,stroke:#d32f2f,stroke-width:2px
    classDef target fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    
    class Target target"""
        
        return f"""
<div class="diagram-container">
    <h3>🎯 Attack Flow - Scenario {safe_scenario_id}</h3>
    <div class="mermaid" id="diagram-{safe_scenario_id}">
        {mermaid}
    </div>
</div>"""
    
    async def parse_and_generate_diagrams(self, report_content: str, threats, product_name: str) -> str:
        """Parse scenarios and generate diagrams using batch processing"""
        # Find unique scenarios using the dedicated parser
        scenarios_found = self.scenario_parser.find_scenarios(report_content)
        
        if not scenarios_found:
            return report_content
        
        # Generate all diagrams in batch
        diagrams = await self.generate_batch_diagrams(scenarios_found, threats, product_name)
        
        # Replace placeholders with generated diagrams
        for scenario_id, diagram_html in diagrams.items():
            report_content = self.scenario_parser.replace_placeholders(report_content, scenario_id, diagram_html)
        
        return report_content
    
    def create_fallback_diagram(self, scenario_id: str, scenario_title: str, product_name: str) -> str:
        """Create a simple fallback diagram"""
        import html
        safe_product_name = html.escape(product_name[:30])
        safe_scenario_id = html.escape(str(scenario_id))
        
        return f"""
<div class="diagram-container">
    <h3>🎯 Attack Flow - Scenario {safe_scenario_id}</h3>
    <div class="mermaid" id="diagram-{safe_scenario_id}">
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
            report_content = self.formatter.clean_llm_response(report_content)
            
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
    
    def _generate_basic_report(self, all_data: Dict[str, Any]) -> str:
        """Generate basic fallback report when full generation fails"""
        product_name = all_data.get('product_name', 'Unknown Product')
        threats = all_data.get('threats', [])
        
        threat_count = len(threats)
        high_severity = len([t for t in threats if t.get('severity') == 'HIGH'])
        critical_severity = len([t for t in threats if t.get('severity') == 'CRITICAL'])
        
        return f"""
        <h1>Threat Assessment Report - {product_name}</h1>
        
        <h2>Executive Summary</h2>
        <p>This assessment identified <strong>{threat_count} potential threats</strong> for {product_name}.</p>
        <ul>
            <li>Critical threats: {critical_severity}</li>
            <li>High severity threats: {high_severity}</li>
            <li>Assessment completed with basic analysis</li>
        </ul>
        
        <h2>Key Findings</h2>
        <p>The following threats were identified:</p>
        <ul>
        {''.join([f'<li><strong>{t.get("title", "Unknown")}</strong> - {t.get("severity", "Unknown")} severity (CVE: {t.get("cve_id", "N/A")})</li>' for t in threats[:10]])}
        </ul>
        
        <h2>Recommendations</h2>
        <ul>
            <li>Implement multi-factor authentication</li>
            <li>Keep software updated with latest security patches</li>
            <li>Deploy network segmentation and monitoring</li>
            <li>Establish incident response procedures</li>
            <li>Conduct regular security assessments</li>
        </ul>
        """
    
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