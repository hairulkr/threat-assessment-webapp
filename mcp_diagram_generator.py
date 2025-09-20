from typing import Dict, Any, List
import subprocess
import os
import re

class MCPDiagramGenerator:
    """Diagram generator with LLM context analysis"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
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
        """Generate attack flow diagram based on threat intelligence and scenario phases"""
        try:
            # Extract phases from scenario text - look for the 7-phase structure
            phase_patterns = [
                r'Phase (\d+):\s*([^\n]+?)\s*\(([^)]+)\)',  # Phase X: Description (MITRE)
                r'\*\*Phase (\d+):[^*]*?\*\*([^\n]+)',  # **Phase X:** Description
                r'Phase (\d+):[^\n]*?([A-Z][^\n]+)',  # Phase X: Description
            ]
            
            phases = []
            
            # Try to extract phases
            for pattern in phase_patterns:
                matches = re.finditer(pattern, scenario_text, re.DOTALL | re.IGNORECASE)
                for match in matches:
                    if len(match.groups()) >= 3:
                        phase_num = match.group(1)
                        phase_desc = match.group(2).strip()
                        mitre_id = match.group(3).strip()
                    else:
                        phase_num = match.group(1)
                        phase_desc = match.group(2).strip() if len(match.groups()) > 1 else f"Phase {phase_num}"
                        mitre_id = 'T????'
                    
                    # Extract MITRE ID if present
                    mitre_match = re.search(r'T\d{4}(?:\.\d{3})?', mitre_id)
                    if mitre_match:
                        mitre_id = mitre_match.group(0)
                    
                    # Clean phase description
                    phase_desc = re.sub(r'<[^>]+>', '', phase_desc)
                    phase_desc = phase_desc.replace('\n', ' ').strip()
                    
                    if phase_desc and len(phase_desc) > 5:
                        phases.append((phase_desc[:40], mitre_id))
                
                if phases:
                    break
            
            # If no phases found, create scenario-specific attack flow
            if not phases:
                phases = self.create_scenario_specific_attack_flow(scenario_text, scenario_id, threats)
            
            # Final fallback: use standard attack phases
            if not phases:
                phases = [
                    ("Reconnaissance", "T1595"),
                    ("Initial Access", "T1190"),
                    ("Execution", "T1059"),
                    ("Persistence", "T1053"),
                    ("Privilege Escalation", "T1068"),
                    ("Defense Evasion", "T1070"),
                    ("Impact", "T1486")
                ]
            
            print(f"Generated {len(phases)} phases for Scenario {scenario_id}")

            # Generate threat intelligence-specific Mermaid diagram
            mermaid_code = self.generate_threat_specific_attack_flow(phases, scenario_id, product_name, threats)

            return self.generate_mermaid_html(mermaid_code, f"🎯 Attack Flow - Scenario {scenario_id}")

        except Exception as e:
            print(f"Scenario {scenario_id} diagram failed: {e}")
            return self.generate_mermaid_html(
                f"graph LR\n    A[Scenario {scenario_id} Attack Flow]\n    A --> B[Diagram Generation Failed]", 
                f"Attack Flow - Scenario {scenario_id}"
            )
    
    async def __aenter__(self):
        """Async context manager entry"""
        print("✅ Diagram generator ready")
        return self
    
    def create_scenario_specific_attack_flow(self, scenario_text: str, scenario_id: str, threats: List[Dict[str, Any]]) -> List[tuple]:
        """Create attack flow phases based on scenario type and threat intelligence"""
        phases = []
        
        # Determine scenario type from text
        scenario_lower = scenario_text.lower()
        
        if 'remote code execution' in scenario_lower or 'rce' in scenario_lower or 'remote exploit' in scenario_lower:
            # Remote Code Execution Attack Flow
            phases = [
                ("Vulnerability Discovery", "T1595"),
                ("Payload Crafting", "T1588.004"),
                ("Code Injection", "T1190"),
                ("Command Execution", "T1059"),
                ("System Compromise", "T1486")
            ]
        elif 'privilege escalation' in scenario_lower or 'privesc' in scenario_lower:
            # Privilege Escalation Attack Flow
            phases = [
                ("Initial Access", "T1078"),
                ("User Enumeration", "T1087"),
                ("Privilege Discovery", "T1033"),
                ("Exploit Weakness", "T1068"),
                ("Admin Access", "T1078.003")
            ]
        elif 'data exfiltration' in scenario_lower or 'data breach' in scenario_lower:
            # Data Exfiltration Attack Flow
            phases = [
                ("Access Gained", "T1190"),
                ("Data Discovery", "T1083"),
                ("Data Classification", "T1005"),
                ("Exfiltration Prep", "T1074"),
                ("External Transfer", "T1041")
            ]
        elif 'sql injection' in scenario_lower or 'sqli' in scenario_lower:
            # SQL Injection Attack Flow
            phases = [
                ("Input Field Discovery", "T1595"),
                ("SQL Injection Test", "T1190"),
                ("Database Enumeration", "T1083"),
                ("Schema Discovery", "T1005"),
                ("Data Extraction", "T1041")
            ]
        elif 'cross-site scripting' in scenario_lower or 'xss' in scenario_lower:
            # XSS Attack Flow
            phases = [
                ("Input Validation Bypass", "T1190"),
                ("Script Injection", "T1059.007"),
                ("User Interaction", "T1204"),
                ("Session Hijacking", "T1539"),
                ("Account Takeover", "T1078")
            ]
        elif 'buffer overflow' in scenario_lower:
            # Buffer Overflow Attack Flow
            phases = [
                ("Buffer Analysis", "T1595"),
                ("Overflow Point Discovery", "T1068"),
                ("Shellcode Development", "T1588.004"),
                ("Memory Corruption", "T1055"),
                ("Code Execution", "T1059")
            ]
        elif 'authentication bypass' in scenario_lower or 'auth bypass' in scenario_lower:
            # Authentication Bypass Attack Flow
            phases = [
                ("Auth Mechanism Analysis", "T1595"),
                ("Weakness Identification", "T1552"),
                ("Bypass Technique", "T1078"),
                ("Unauthorized Access", "T1078.004"),
                ("System Compromise", "T1486")
            ]
        elif 'availability' in scenario_lower or 'denial of service' in scenario_lower or 'dos' in scenario_lower:
            # Availability Attack Flow
            phases = [
                ("Target Identification", "T1595"),
                ("Resource Exhaustion", "T1499"),
                ("Service Disruption", "T1499.004"),
                ("System Overload", "T1499.002"),
                ("Service Unavailable", "T1485")
            ]
        elif 'supply chain' in scenario_lower or 'dependency' in scenario_lower:
            # Supply Chain Attack Flow
            phases = [
                ("Supply Chain Analysis", "T1195"),
                ("Malicious Component", "T1195.002"),
                ("Software Distribution", "T1195.001"),
                ("Execution via Update", "T1072"),
                ("Widespread Impact", "T1486")
            ]
        else:
            # CVE-specific attack flow based on threat intelligence
            if threats:
                top_threat = threats[0]
                cve_id = top_threat.get('cve_id', 'Unknown')
                description = top_threat.get('description', '').lower()
                
                if 'remote' in description:
                    phases = [
                        (f"CVE {cve_id} Discovery", "T1595"),
                        ("Remote Exploitation", "T1190"),
                        ("Code Execution", "T1059"),
                        ("System Compromise", "T1486")
                    ]
                elif 'privilege' in description:
                    phases = [
                        (f"CVE {cve_id} Exploit", "T1068"),
                        ("Privilege Escalation", "T1068"),
                        ("Admin Access", "T1078.003")
                    ]
                else:
                    phases = [
                        (f"CVE {cve_id} Exploit", "T1190"),
                        ("System Impact", "T1486")
                    ]
        
        return phases if phases else []
    
    def generate_threat_specific_attack_flow(self, phases: List[tuple], scenario_id: str, product_name: str, threats: List[Dict[str, Any]]) -> str:
        """Generate threat intelligence-specific Mermaid diagram"""
        if not phases:
            return f"graph TD\n    A[\"Scenario {scenario_id}: No Attack Flow\"]"

        # Clean product name for Mermaid
        clean_product = product_name.replace('"', '').replace("'", '').replace('\n', ' ')[:25]
        
        # Get threat context for diagram
        threat_context = ""
        if threats:
            top_threat = threats[0]
            cve_id = top_threat.get('cve_id', '')
            severity = top_threat.get('severity', '')
            if cve_id:
                threat_context = f"\\n{cve_id} ({severity})"

        # Build threat-specific attack flow
        mermaid = f"graph TD\n    Target[\"🎯 {clean_product}{threat_context}\"]\n"
        
        # Add each phase with threat intelligence context
        for i, (phase_desc, mitre_id) in enumerate(phases, 1):
            phase_name = f"Phase{i}"
            
            # Clean and format description
            clean_desc = phase_desc.replace('"', '').replace("'", '').replace('\n', ' ').strip()[:35]
            clean_mitre = mitre_id.strip()
            
            # Add phase node with threat intelligence context
            mermaid += f"    {phase_name}[\"{clean_desc}\\n{clean_mitre}\"]\n"
            
            # Connect phases
            if i == 1:
                mermaid += f"    Target --> {phase_name}\n"
            else:
                prev_phase = f"Phase{i-1}"
                mermaid += f"    {prev_phase} --> {phase_name}\n"
        
        # Add final outcome based on threat severity
        if threats and threats[0].get('severity') in ['CRITICAL', 'HIGH']:
            mermaid += f"    Phase{len(phases)} --> Compromise[\"🚨 System Compromise\"]\n\n"
        else:
            mermaid += f"    Phase{len(phases)} --> Impact[\"⚠️ Security Impact\"]\n\n"
        
        # Add threat intelligence-based styling
        mermaid += """    classDef default fill:#f9f9f9,stroke:#333,stroke-width:2px
    classDef critical fill:#ffebee,stroke:#d32f2f,stroke-width:3px
    classDef high fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef target fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    
    class Target target"""
        
        # Apply severity-based styling
        if threats:
            severity = threats[0].get('severity', 'UNKNOWN')
            if severity == 'CRITICAL':
                mermaid += "\n    class Compromise critical"
            elif severity == 'HIGH':
                mermaid += "\n    class Impact high"
        
        return mermaid
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        pass