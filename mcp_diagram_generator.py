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
        
        # Multiple patterns to find scenarios - more robust approach
        patterns = [
            r'SCENARIO ([A-Z]):[^\[]*?\[DIAGRAM_PLACEHOLDER_SCENARIO_([A-Z])\]',  # Direct match with placeholder
            r'SCENARIO ([A-Z]):.*?(?=SCENARIO [A-Z]:|$)',  # Match until next scenario or end
            r'(?:^|\n)\s*SCENARIO ([A-Z]):.*?(?=(?:^|\n)\s*SCENARIO [A-Z]:|$)'  # Line-based matching
        ]
        
        # Also find all placeholders to ensure we generate diagrams for all
        placeholder_pattern = r'\[DIAGRAM_PLACEHOLDER_SCENARIO_([A-Z])\]'
        placeholders = re.findall(placeholder_pattern, report_content)
        
        print(f"Found placeholders for scenarios: {placeholders}")
        
        # Generate diagrams for each found placeholder
        for scenario_id in placeholders:
            print(f"🖼️ Generating diagram for Scenario {scenario_id}...")
            
            # Find the scenario text using multiple patterns
            scenario_text = ""
            for pattern in patterns:
                matches = re.finditer(pattern, report_content, re.DOTALL | re.MULTILINE)
                for match in matches:
                    if match.group(1) == scenario_id:
                        scenario_text = match.group(0)
                        break
                if scenario_text:
                    break
            
            if not scenario_text:
                # Fallback: extract text around the placeholder
                placeholder_pos = report_content.find(f'[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id}]')
                if placeholder_pos > 0:
                    # Get 1000 characters before the placeholder
                    start = max(0, placeholder_pos - 1000)
                    scenario_text = report_content[start:placeholder_pos]
            
            print(f"Scenario Text Length: {len(scenario_text)}")
            
            # Generate diagram for this specific scenario
            try:
                diagram_html = await self.generate_scenario_diagram(scenario_text, scenario_id, threats, product_name)
                print(f"✅ Generated diagram HTML for Scenario {scenario_id}")
            except Exception as e:
                print(f"⚠️ Diagram generation failed for Scenario {scenario_id}: {e}")
                diagram_html = f"<div class='diagram-error'>Diagram generation failed for Scenario {scenario_id}</div>"

            # Replace placeholder with diagram
            placeholder = f'[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id}]'
            report_content = report_content.replace(placeholder, diagram_html)

        return report_content
    
    async def generate_scenario_diagram(self, scenario_text: str, scenario_id: str, threats: List[Dict[str, Any]], product_name: str) -> str:
        """Generate attack flow diagram for a specific scenario"""
        try:
            # Multiple patterns to extract steps - more robust
            step_patterns = [
                r'Step (\d+):\s*([^(]+?)\s*\(([^)]+)\)',  # Step X: Description (MITRE)
                r'Step (\d+):\s*([^\n]+?)\s*\(([^)]+)\)',  # Step X: Description (MITRE) - single line
                r'Step (\d+):\s*([^\n]+)',  # Step X: Description - no MITRE
                r'(\d+)\.[^:]*:\s*([^(]+?)\s*\(([^)]+)\)',  # Numbered sections with MITRE
            ]
            
            steps = []
            
            # Try each pattern
            for pattern in step_patterns:
                matches = re.finditer(pattern, scenario_text, re.DOTALL)
                for match in matches:
                    if len(match.groups()) >= 3:
                        step_num = match.group(1)
                        step_desc = match.group(2).strip()
                        mitre_id = match.group(3).strip()
                    else:
                        step_num = match.group(1)
                        step_desc = match.group(2).strip()
                        mitre_id = 'T????'
                    
                    # Clean up MITRE ID
                    mitre_match = re.search(r'T\d{4}(?:\.\d{3})?', mitre_id)
                    if mitre_match:
                        mitre_id = mitre_match.group(0)
                    
                    # Clean step description
                    step_desc = re.sub(r'<[^>]+>', '', step_desc)  # Remove HTML tags
                    step_desc = step_desc.replace('\n', ' ').strip()
                    
                    if step_desc and len(step_desc) > 5:  # Valid step
                        steps.append((step_desc[:50], mitre_id))  # Limit length
                
                if steps:  # If we found steps with this pattern, use them
                    break
            
            # Fallback: create generic steps if none found
            if not steps:
                steps = [
                    (f"Attack Step for Scenario {scenario_id}", "T1566"),
                    ("Execution Phase", "T1059"),
                    ("Impact Phase", "T1485")
                ]
                print(f"No steps found, using generic steps for Scenario {scenario_id}")
            
            print(f"Extracted {len(steps)} steps for Scenario {scenario_id}: {[s[0][:30] for s in steps]}")

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
        try:
            await self.mcp_client.start_server()
            print("✅ MCP server started successfully")
        except Exception as e:
            print(f"⚠️ MCP server failed to start: {e}")
        return self
    
    def generate_custom_attack_flow(self, steps: List[tuple], scenario_id: str, product_name: str) -> str:
        """Generate custom Mermaid diagram from parsed attack steps"""

        if not steps:
            return f"graph TD\n    A[\"Scenario {scenario_id}: No Steps Found\"]"

        # Clean product name for Mermaid
        clean_product = product_name.replace('"', '').replace("'", '').replace('\n', ' ')[:25]

        # Simplified attack flow - more reliable
        mermaid = f"graph TD\n    Start[\"Target: {clean_product}\"]\n"
        
        # Add each step in sequence
        for i, (step_desc, mitre_id) in enumerate(steps, 1):
            step_name = f"Step{i}"
            
            # Clean and shorten description
            clean_desc = step_desc.replace('"', '').replace("'", '').replace('\n', ' ').strip()[:40]
            clean_mitre = mitre_id.strip()
            
            # Add step node
            mermaid += f"    {step_name}[\"{clean_desc}\\n({clean_mitre})\"]"
            
            # Connect to previous step or start
            if i == 1:
                mermaid += f"\n    Start --> {step_name}\n"
            else:
                mermaid += f"\n    Step{i-1} --> {step_name}\n"
        
        # Add final outcome
        mermaid += f"    Step{len(steps)} --> End[\"Attack Complete\"]\n"
        
        # Add styling
        mermaid += "\n    classDef default fill:#f9f9f9,stroke:#333,stroke-width:2px\n"
        mermaid += "    classDef critical fill:#ffebee,stroke:#d32f2f,stroke-width:3px\n"
        mermaid += "    classDef start fill:#e8f5e8,stroke:#4caf50,stroke-width:2px\n"
        mermaid += "    \n    class Start start\n"
        mermaid += "    class End critical\n"

        return mermaid
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        try:
            await self.mcp_client.close()
        except Exception as e:
            print(f"⚠️ MCP server close error: {e}")