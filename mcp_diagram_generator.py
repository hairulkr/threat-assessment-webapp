from typing import Dict, Any, List
from mcp_client import MermaidMCPClient
import subprocess
import os
import re

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
    
    def generate_mermaid_image(self, diagram_code: str, scenario_id: str) -> str:
        """Generate an image from Mermaid diagram code using Mermaid CLI"""
        diagrams_dir = "reports/diagrams"
        os.makedirs(diagrams_dir, exist_ok=True)

        # File paths
        mermaid_file = os.path.join(diagrams_dir, f"scenario_{scenario_id}.mmd")
        image_file = os.path.join(diagrams_dir, f"scenario_{scenario_id}.png")

        # Write the Mermaid code to a file
        with open(mermaid_file, "w") as file:
            file.write(diagram_code)

        # Generate the image using Mermaid CLI
        try:
            subprocess.run([
                "mmdc", "-i", mermaid_file, "-o", image_file
            ], check=True)
            return image_file
        except subprocess.CalledProcessError as e:
            print(f"Mermaid CLI failed: {e}")
            return None

    
    async def insert_scenario_diagrams(self, threats: List[Dict[str, Any]], product_name: str, report_content: str) -> str:
        """Insert attack flow diagrams after each attack scenario"""
        
        print("🔗 Connecting to Mermaid MCP server...")
        print("🎯 Generating diagrams for each attack scenario...")
        
        # Find and replace diagram placeholders
        # Find all scenario placeholders
        placeholders = re.findall(r'\[DIAGRAM_PLACEHOLDER_SCENARIO_([A-Z0-9]+)\]', report_content)
        print("🔍 Full Report Content:")
        print(report_content)
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

        # Define color codes for different MITRE categories
        category_colors = {
            "Initial Access": "#ff9999",
            "Execution": "#ffcc99",
            "Persistence": "#ffff99",
            "Privilege Escalation": "#ccff99",
            "Defense Evasion": "#99ff99",
            "Credential Access": "#99ffcc",
            "Discovery": "#99ccff",
            "Lateral Movement": "#9999ff",
            "Collection": "#cc99ff",
            "Exfiltration": "#ff99cc",
            "Impact": "#ff6699"
        }

        mermaid = f"graph TD\n    Start[\"Target: {clean_product}\"] --> Step1\n"

        for i, (step_desc, mitre_id) in enumerate(steps, 1):
            step_name = f"Step{i}"
            decision_name = f"Decision{i}"

            # Determine the category color
            category = "Unknown"
            for cat in category_colors:
                if cat in step_desc:
                    category = cat
                    break

            color = category_colors.get(category, "#d3d3d3")  # Default to gray if category is unknown

            # Add the step node with color
            mermaid += f"    {step_name}[\"{step_desc} ({mitre_id})\"]:::step{i}\n"
            mermaid += f"    classDef step{i} fill:{color},stroke:#000,stroke-width:2px;\n"

            # Add a decision node after each step
            mermaid += f"    {step_name} --> {decision_name}{{\"Mitigation Decision\"}}\n"

            # Add paths for the decision node
            mermaid += f"    {decision_name} -->|Mitigated| Step{i+1 if i < len(steps) else 'End'}\n"
            mermaid += f"    {decision_name} -->|Not Mitigated| Step{i+1 if i < len(steps) else 'End'}\n"

        # Add an end node
        mermaid += "    End[\"Attack Flow Complete\"]\n"

        return mermaid
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.mcp_client.close()