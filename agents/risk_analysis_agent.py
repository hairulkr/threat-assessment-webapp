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
        # Optimize: Only analyze top 3 threats for token efficiency
        top_threats = [{'title': t.get('title', '')[:50], 'severity': t.get('severity', ''), 'cvss_score': t.get('cvss_score', 0)} for t in threats[:3]]
        
        analysis_prompt = f"""
        Risk analysis for {product_info.get('name', 'Product')}:
        
        TOP 3 THREATS: {json.dumps(top_threats)}
        
        JSON response:
        {{
            "overall_risk_level": "CRITICAL/HIGH/MEDIUM/LOW",
            "risk_score": 8.5,
            "threat_analysis": [{{"threat_id": "CVE-ID", "risk_level": "HIGH", "mitre_technique": "T1190"}}],
            "mitre_mapping": [{{"technique": "T1190", "tactic": "Initial Access"}}],
            "recommendations": ["Action 1", "Action 2"]
        }}
        """
        
        try:
            response = await self.llm.generate(analysis_prompt, max_tokens=600)
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