"""LLM-driven MITRE-mapped security controls generation"""
import json
import asyncio
from typing import List, Dict, Any

class ControlsAgent:
    """Generate MITRE ATT&CK mapped security controls"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    async def generate_mitre_controls(self, threats: List[Dict], risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Step 2: Generate MITRE-mapped controls based on ranked threats"""
        
        if not threats:
            return self._get_mitre_fallback_controls(['T1190'])
        
        # Extract MITRE techniques from threats
        mitre_techniques = list(set([t.get('mitre_technique', 'T1190') for t in threats[:8]]))
        threat_summary = '\n'.join([f"- {t.get('title', 'Unknown')} ({t.get('mitre_technique', 'T1190')})" for t in threats[:5]])
        
        prompt = f"""Generate MITRE ATT&CK mapped security controls for these threats:

{threat_summary}

MITRE Techniques: {', '.join(mitre_techniques)}
Risk Level: {risk_assessment.get('overall_risk_level', 'MEDIUM')}

Return JSON with MITRE-mapped controls:
{{
  "preventive": [
    {{"control": "Multi-factor Authentication", "mitre_mitigation": "M1032", "techniques": ["T1078"]}}
  ],
  "detective": [
    {{"control": "Network Monitoring", "mitre_mitigation": "M1047", "techniques": ["T1190"]}}
  ],
  "corrective": [
    {{"control": "Incident Response Plan", "mitre_mitigation": "M1049", "techniques": ["T1486"]}}
  ]
}}

Return ONLY JSON."""
        
        try:
            response = await asyncio.wait_for(
                self.llm.generate(prompt, max_tokens=1500),
                timeout=90
            )
            
            # Parse JSON response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                controls = json.loads(json_match.group(0))
                print(f"   🛡️ Generated MITRE-mapped controls for {len(mitre_techniques)} techniques")
                return controls
            
        except Exception as e:
            print(f"   ⚠️ MITRE control generation failed: {e}")
        
        return self._get_mitre_fallback_controls(mitre_techniques)
    
    def _get_mitre_fallback_controls(self, techniques: List[str]) -> Dict[str, Any]:
        """MITRE-mapped fallback controls"""
        return {
            "preventive": [
                {"control": "Multi-factor Authentication", "mitre_mitigation": "M1032", "techniques": ["T1078"]},
                {"control": "Network Segmentation", "mitre_mitigation": "M1030", "techniques": ["T1190"]},
                {"control": "Application Isolation", "mitre_mitigation": "M1048", "techniques": ["T1055"]}
            ],
            "detective": [
                {"control": "Network Monitoring", "mitre_mitigation": "M1047", "techniques": ["T1190"]},
                {"control": "Process Monitoring", "mitre_mitigation": "M1047", "techniques": ["T1059"]},
                {"control": "File Monitoring", "mitre_mitigation": "M1047", "techniques": ["T1005"]}
            ],
            "corrective": [
                {"control": "Incident Response Plan", "mitre_mitigation": "M1049", "techniques": techniques},
                {"control": "Backup and Recovery", "mitre_mitigation": "M1053", "techniques": ["T1486"]},
                {"control": "Threat Hunting", "mitre_mitigation": "M1047", "techniques": techniques}
            ]
        }