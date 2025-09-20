from typing import Dict, Any, List
from mcp_client import MermaidMCPClient

class MCPDiagramGenerator:
    """MCP-powered diagram generator with LLM context analysis"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.mcp_client = MermaidMCPClient()
    
    def generate_mermaid_html(self, diagram_code: str, title: str = "") -> str:
        """Generate HTML with embedded Mermaid diagram"""
        return f"""
        <div class="diagram-container">
            <h3>{title}</h3>
            <div class="mermaid">
                {diagram_code}
            </div>
        </div>
        """
    

    
    async def insert_scenario_diagrams(self, threats: List[Dict[str, Any]], product_name: str, report_content: str) -> str:
        """Insert attack flow diagrams after each attack scenario"""
        
        print("🔗 Connecting to Mermaid MCP server...")
        print("🎯 Generating diagrams for each attack scenario...")
        
        # Find and replace diagram placeholders
        import re
        
        # Find all scenario placeholders
        placeholders = re.findall(r'\[DIAGRAM_PLACEHOLDER_SCENARIO_([A-Z0-9]+)\]', report_content)
        print("🔍 Found placeholders:", placeholders)

        for scenario_id in placeholders:
            # Extract the specific scenario content
            scenario_pattern = f'SCENARIO {scenario_id}:.*?(?=SCENARIO [A-Z0-9]+:|\\[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id}\\]|$)'
            scenario_match = re.search(scenario_pattern, report_content, re.DOTALL)

            if scenario_match:
                scenario_text = scenario_match.group(0)
                print(f"🖼️ Generating diagram for Scenario {scenario_id}...")
                print(f"Scenario Text: {scenario_text}")

                # Generate diagram for this specific scenario
                try:
                    diagram_html = await self.generate_scenario_diagram(scenario_text, scenario_id, threats, product_name)
                    print(f"✅ Generated diagram HTML for Scenario {scenario_id}:", diagram_html)
                except Exception as e:
                    print(f"⚠️ Diagram generation failed for Scenario {scenario_id}: {e}")
                    diagram_html = f"<div class='diagram-error'>Diagram generation failed for Scenario {scenario_id}</div>"

                # Replace placeholder with diagram
                placeholder = f'[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id}]'
                report_content = report_content.replace(placeholder, diagram_html)
            else:
                print(f"⚠️ No matching content found for Scenario {scenario_id}")
                placeholder = f'[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id}]'
                report_content = report_content.replace(placeholder, f"<div class='diagram-error'>No content found for Scenario {scenario_id}</div>")
        
        return report_content
    
    async def generate_scenario_diagram(self, scenario_text: str, scenario_id: str, threats: List[Dict[str, Any]], product_name: str) -> str:
        """Generate attack flow diagram for a specific scenario"""
        
        try:
            # Parse attack steps directly from scenario text
            import re
            
            # Extract steps with MITRE techniques
            step_pattern = r'Step \d+:([^(]+)\(([^)]+)\)'
            steps = re.findall(step_pattern, scenario_text)
            
            if not steps:
                # Fallback: extract any numbered steps
                step_pattern = r'Step \d+:([^\n]+)'
                raw_steps = re.findall(step_pattern, scenario_text)
                steps = [(step.strip(), 'T????') for step in raw_steps]
            
            # Generate custom Mermaid diagram based on actual steps
            mermaid_code = self.generate_custom_attack_flow(steps, scenario_id, product_name)
            
            return self.generate_mermaid_html(mermaid_code, f"🎯 Attack Flow - Scenario {scenario_id}")
            
        except Exception as e:
            print(f"Scenario {scenario_id} diagram failed: {e}")
            return self.generate_mermaid_html(
                f"graph LR\n    A[Scenario {scenario_id} Attack Flow]\n    A --> B[Diagram Generation Failed]", 
                f"Attack Flow - Scenario {scenario_id}"
            )
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.mcp_client.start_server()
        return self
    
    def generate_custom_attack_flow(self, steps: List[tuple], scenario_id: str, product_name: str) -> str:
        """Generate custom Mermaid diagram from parsed attack steps"""
        
        if not steps:
            return f"graph LR\n    A[\"No attack steps found for Scenario {scenario_id}\"]"
        
        # Clean product name for Mermaid
        clean_product = product_name.replace('"', '').replace("'", '').replace('\n', ' ')[:30]
        
        mermaid = f"graph LR\n    Start[\"Target: {clean_product}\"] --> Step1\n"
        
        # Generate nodes for each step
        for i, (step_desc, mitre_id) in enumerate(steps, 1):
            step_name = f"Step{i}"
            # Clean description for Mermaid syntax
            clean_desc = step_desc.strip().replace('"', '').replace("'", '').replace('\n', ' ')[:35]
            clean_mitre = mitre_id.strip().replace('"', '').replace("'", '')
            
            mermaid += f"    {step_name}[\"{clean_desc}<br/>{clean_mitre}\"]\n"
            
            # Connect to next step
            if i < len(steps):
                mermaid += f"    {step_name} --> Step{i+1}\n"
            else:
                mermaid += f"    {step_name} --> End[\"Attack Complete\"]\n"
        
        # Add styling
        mermaid += "\n    classDef critical fill:#dc3545,stroke:#721c24,color:#fff\n"
        mermaid += "    classDef mitre fill:#6f42c1,stroke:#59359a,color:#fff\n"
        mermaid += "    classDef target fill:#28a745,stroke:#1e7e34,color:#fff\n"
        
        # Apply styles to critical steps
        critical_steps = [f"Step{i+1}" for i, (desc, _) in enumerate(steps) if any(word in desc.lower() for word in ['exploit', 'execute', 'escalate', 'exfiltrate'])]
        if critical_steps:
            mermaid += f"    class {','.join(critical_steps)} critical\n"
        
        mermaid += "    class Start,End target\n"
        
        return mermaid
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.mcp_client.close()