import json
from typing import List, Dict, Any

class RiskAnalysisAgent:
    """LLM-powered risk analysis with MITRE ATT&CK mapping"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    async def analyze_risks(self, product_info: Dict[str, Any], threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze risks and map to MITRE ATT&CK framework"""
        
        print("   Analyzing threat risks and MITRE techniques...")
        
        # LLM analyzes threats and maps to MITRE techniques
        analysis_prompt = f"""
        Analyze cybersecurity risks for {product_info.get('name', 'Unknown Product')}:
        
        THREATS FOUND:
        {json.dumps([{'title': t.get('title', ''), 'severity': t.get('severity', ''), 'cvss_score': t.get('cvss_score', 0)} for t in threats[:5]], indent=2)}
        
        Provide comprehensive risk analysis in JSON format:
        {{
            "overall_risk_level": "CRITICAL/HIGH/MEDIUM/LOW",
            "risk_score": 8.5,
            "threat_analysis": [
                {{
                    "threat_id": "CVE-2024-1234",
                    "risk_level": "HIGH",
                    "attack_vector": "Network",
                    "impact": "Complete system compromise",
                    "likelihood": "HIGH",
                    "mitre_technique": "T1190",
                    "business_impact": "Data breach, service disruption"
                }}
            ],
            "mitre_mapping": [
                {{"technique": "T1190", "tactic": "Initial Access", "description": "Exploit Public-Facing Application"}},
                {{"technique": "T1059", "tactic": "Execution", "description": "Command and Scripting Interpreter"}}
            ],
            "recommendations": ["Implement WAF", "Update vulnerable components"]
        }}
        
        Focus on realistic MITRE ATT&CK techniques that match the identified threats.
        """
        
        try:
            response = await self.llm.generate(analysis_prompt, max_tokens=800)
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                risk_analysis = json.loads(json_match.group())
                print(f"   Risk analysis complete - Overall risk: {risk_analysis.get('overall_risk_level', 'UNKNOWN')}")
                return risk_analysis
        except Exception as e:
            print(f"   Risk analysis failed: {e}")
        
        # Fallback risk analysis
        return {
            "overall_risk_level": "MEDIUM",
            "risk_score": 6.0,
            "threat_analysis": [
                {
                    "threat_id": t.get("cve_id", "Unknown"),
                    "risk_level": t.get("severity", "MEDIUM"),
                    "attack_vector": "Network",
                    "impact": "System compromise",
                    "likelihood": "MEDIUM",
                    "mitre_technique": "T1190",
                    "business_impact": "Potential data exposure"
                } for t in threats[:3]
            ],
            "mitre_mapping": [
                {"technique": "T1190", "tactic": "Initial Access", "description": "Exploit Public-Facing Application"}
            ],
            "recommendations": ["Apply security patches", "Implement monitoring"]
        }