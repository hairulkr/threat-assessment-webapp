import json
from typing import List, Dict, Any

class ControlsAgent:
    """LLM-powered security controls proposal"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    async def propose_controls(self, risks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        prompt = f"""
        Analyze these risks and propose security controls that map to specific attack steps:
        
        RISKS: {json.dumps(risks, indent=2)}
        
        For each control, specify:
        - control_id (C001, C002, etc.)
        - type (Technical, Administrative, Physical)
        - description (detailed implementation)
        - priority (CRITICAL, HIGH, MEDIUM, LOW)
        - attack_step_addressed (which specific attack step this control mitigates)
        - implementation_guidance (how to implement)
        
        Return JSON array with these fields.
        """
        response = await self.llm.generate(prompt, max_tokens=800)
        try:
            return json.loads(response)
        except:
            return []