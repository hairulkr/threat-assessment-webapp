from typing import Dict, Any, List
import subprocess
import os
import re
import logging

class MCPDiagramGenerator:
    """Diagram generator with LLM context analysis"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    def generate_mermaid_html(self, diagram_code: str, title: str = "") -> str:
        """Generate HTML with embedded Mermaid diagram"""
        import html
        safe_title = html.escape(title)
        safe_diagram_code = html.escape(diagram_code)
        return f"""
        <div class="diagram-container">
            <h3>{safe_title}</h3>
            <div class="mermaid">
                {safe_diagram_code}
            </div>
        </div>
        """
    
    def generate_mermaid_image(self, diagram_code: str, scenario_id: str) -> str:
        """Generate an image from Mermaid diagram code using Mermaid CLI"""
        diagrams_dir = "reports/diagrams"
        os.makedirs(diagrams_dir, exist_ok=True)

        # Validate scenario_id to prevent path traversal and command injection
        safe_scenario_id = re.sub(r'[^a-zA-Z0-9_-]', '', str(scenario_id))
        if not safe_scenario_id or len(safe_scenario_id) > 50:
            safe_scenario_id = 'default'
        # Additional validation to prevent command injection
        if any(char in safe_scenario_id for char in ['..', '/', '\\', ';', '&', '|', '`']):
            safe_scenario_id = 'default'
        
        # File paths with validation
        mermaid_file = os.path.abspath(os.path.join(diagrams_dir, f"scenario_{safe_scenario_id}.mmd"))
        image_file = os.path.abspath(os.path.join(diagrams_dir, f"scenario_{safe_scenario_id}.png"))
        
        # Ensure files are within the diagrams directory
        safe_diagrams_dir = os.path.abspath(diagrams_dir)
        if not mermaid_file.startswith(safe_diagrams_dir) or not image_file.startswith(safe_diagrams_dir):
            raise ValueError("Path traversal attempt detected")

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

    

    
    async def generate_scenario_diagram(self, scenario_text: str, scenario_id: str, threats: List[Dict[str, Any]], product_name: str) -> str:
        """Generate attack flow diagram based on actual scenario content and phases"""
        try:
            # Extract actual attack steps from scenario content
            phases = await self.extract_actual_attack_phases(scenario_text, scenario_id, threats)
            
            logging.info(f"Extracted {len(phases)} actual phases for Scenario {scenario_id}: {[p[0] for p in phases]}")

            # Generate threat intelligence-specific Mermaid diagram
            mermaid_code = self.generate_threat_specific_attack_flow(phases, scenario_id, product_name, threats)

            return self.generate_mermaid_html(mermaid_code, f"🎯 Attack Flow - Scenario {scenario_id}")

        except Exception as e:
            logging.error(f"Scenario {scenario_id} diagram failed: {e}")
            return self.generate_mermaid_html(
                f"graph LR\n    A[Scenario {scenario_id} Attack Flow]\n    A --> B[Diagram Generation Failed]", 
                f"Attack Flow - Scenario {scenario_id}"
            )
    
    async def extract_actual_attack_phases(self, scenario_text: str, scenario_id: str, threats: List[Dict[str, Any]]) -> List[tuple]:
        """Extract actual attack phases from scenario content using LLM analysis"""
        
        print(f"🔍 Analyzing scenario {scenario_id} with {len(scenario_text)} chars")
        
        # Use LLM to analyze scenario and extract attack phases
        analysis_prompt = f"""
        Analyze this attack scenario and extract the specific attack phases mentioned:
        
        SCENARIO TEXT:
        {scenario_text[:2000]}
        
        Extract the actual attack steps/phases mentioned in this scenario. Look for:
        - Step-by-step attack progression
        - Technical attack methods
        - Specific tools or techniques mentioned
        - MITRE ATT&CK techniques if present
        
        Return ONLY a numbered list of attack phases in this format:
        1. Phase Name - MITRE_ID
        2. Phase Name - MITRE_ID
        
        Example:
        1. CVE-2023-1234 Exploitation - T1190
        2. Reverse Shell Establishment - T1059
        3. Privilege Escalation via sudo - T1068
        
        Focus on the ACTUAL attack steps described in the scenario, not generic phases.
        """
        
        try:
            llm_response = await self.llm.generate(analysis_prompt, max_tokens=300)
            print(f"🤖 LLM response: {llm_response[:200]}...")
            
            # Parse LLM response to extract phases
            phases = []
            lines = llm_response.strip().split('\n')
            
            for line in lines:
                # Match numbered list format: "1. Phase Name - T1234"
                match = re.match(r'\d+\.\s*([^-]+)\s*-\s*(T\d{4}(?:\.\d{3})?)', line.strip())
                if match:
                    phase_name = match.group(1).strip()[:40]
                    mitre_id = match.group(2).strip()
                    phases.append((phase_name, mitre_id))
            
            print(f"📊 LLM extracted {len(phases)} phases: {[p[0] for p in phases]}")
            
            # If LLM extraction failed, fall back to pattern matching
            if not phases:
                print(f"🔄 LLM failed, trying pattern matching...")
                phases = self.extract_phases_from_text(scenario_text)
                print(f"📊 Pattern extracted {len(phases)} phases: {[p[0] for p in phases]}")
            
            # Final fallback to scenario-specific flow
            if not phases:
                print(f"🔄 Pattern failed, using scenario-specific flow...")
                phases = self.create_scenario_specific_attack_flow(scenario_text, scenario_id, threats)
                print(f"📊 Scenario-specific extracted {len(phases)} phases: {[p[0] for p in phases]}")
            
            return phases[:7]  # Limit to 7 phases max
            
        except Exception as e:
            print(f"⚠️ LLM phase extraction failed: {e}")
            return self.extract_phases_from_text(scenario_text)
    
    def extract_phases_from_text(self, scenario_text: str) -> List[tuple]:
        """Extract phases using pattern matching as fallback"""
        phases = []
        
        # Enhanced patterns to find actual attack steps
        patterns = [
            r'(?:Step|Phase)\s+(\d+)[:\.]\s*([^\n]+?)(?:\s*\(([T]\d{4}(?:\.\d{3})?)\))?',  # Step 1: Description (T1234)
            r'\*\*([^*]+)\*\*[^\n]*?([T]\d{4}(?:\.\d{3})?)',  # **Phase Name** ... T1234
            r'([A-Z][^\n]{10,50})\s*-\s*([T]\d{4}(?:\.\d{3})?)',  # Description - T1234
            r'\d+\.\s*([^\n]{10,60})',  # 1. Description (no MITRE)
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, scenario_text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if len(match.groups()) >= 2:
                    if match.group(1).isdigit():  # Skip if first group is just a number
                        phase_desc = match.group(2).strip()
                        mitre_id = match.group(3) if len(match.groups()) > 2 and match.group(3) else 'T1059'
                    else:
                        phase_desc = match.group(1).strip()
                        mitre_id = match.group(2) if len(match.groups()) > 1 and match.group(2) else 'T1059'
                else:
                    phase_desc = match.group(1).strip() if match.group(1) else 'Attack Phase'
                    mitre_id = 'T1059'
                
                # Clean and validate
                phase_desc = re.sub(r'<[^>]+>', '', phase_desc)
                phase_desc = phase_desc.replace('\n', ' ').strip()[:40]
                
                if len(phase_desc) > 8 and not phase_desc.isdigit():
                    phases.append((phase_desc, mitre_id))
            
            if phases:
                break
        
        return phases[:7]
    
    async def __aenter__(self):
        """Async context manager entry"""
        logging.info("Diagram generator ready")
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