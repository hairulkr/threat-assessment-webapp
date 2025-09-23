import json
import os
from typing import Dict, Any
from datetime import datetime
from mcp_diagram_generator import MCPDiagramGenerator
from .report_formatter import ReportFormatter
from .scenario_parser import ScenarioParser
from .prompt_templates import PromptTemplates

class ReportAgent:
    """LLM-powered comprehensive threat modeling report generation"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.reports_dir = "reports"
        self.diagram_generator = MCPDiagramGenerator(self.llm)
        self.formatter = ReportFormatter()
        self.scenario_parser = ScenarioParser()
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def determine_scenario_types(self, threats):
        """Let LLM determine scenario types dynamically based on threat intelligence"""
        # Return empty list - let LLM analyze threats and create scenarios dynamically
        return []
    
    async def parse_and_generate_diagrams(self, report_content: str, threats, product_name: str) -> str:
        """Parse scenarios from content and generate appropriate diagrams"""
        # Find unique scenarios using the dedicated parser
        scenarios_found = self.scenario_parser.find_scenarios(report_content)
        
        # Generate diagrams for each unique scenario
        for scenario_id, scenario_title in scenarios_found:
            print(f"🎯 Generating diagram for Scenario {scenario_id}: {scenario_title}")
            
            # Extract scenario content
            scenario_content = self.scenario_parser.extract_scenario_content(report_content, scenario_id, scenario_title)
            print(f"📝 Extracted scenario content length: {len(scenario_content)}")
            
            # Generate diagram
            try:
                async with self.diagram_generator as mcp_gen:
                    diagram_html = await mcp_gen.generate_scenario_diagram(scenario_content, scenario_id, threats, product_name)
                print(f"✅ Dynamic diagram generated for {scenario_id}")
            except Exception as e:
                print(f"⚠️ Diagram generation failed for {scenario_id}: {e}")
                diagram_html = self.create_fallback_diagram(scenario_id, scenario_title, product_name)
            
            # Replace placeholder with diagram
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
    
    async def generate_comprehensive_report(self, all_data: Dict[str, Any]) -> str:
        """Generate complete threat modeling report from all collected data"""
        
        # Generate report using standardized prompt
        report_prompt = PromptTemplates.get_comprehensive_report_prompt(all_data)
        report_content = await self.llm.generate(report_prompt, max_tokens=6000)
        
        # Clean and normalize LLM response
        report_content = self.formatter.clean_llm_response(report_content)
        report_content = self.formatter.normalize_html_structure(report_content)
        
        # Generate diagrams for scenarios
        threats = all_data.get('threats', [])
        product_name = all_data.get('product_name', 'Unknown Product')
        report_content = await self.parse_and_generate_diagrams(report_content, threats, product_name)
        
        return report_content
    
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
            
            # Create complete HTML document
            html_template = self.formatter.create_html_template(report_content, product_name)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_template)
            
            print(f"   📄 HTML report saved: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"Error creating HTML report: {e}")
            return f"HTML report creation failed: {e}"