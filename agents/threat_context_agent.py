import json
from typing import List, Dict, Any
# Note: Using optimized threat intel system instead of ThreatIntelSources

class ThreatContextAgent:
    """Enhanced threat intelligence with web context"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    async def gather_threat_context(self, product_name: str, existing_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Gather additional threat context from multiple sources"""
        
        # Note: Web intelligence gathering disabled - using optimized threat intel system
        web_intel = []
        
        if not web_intel:
            return {
                "web_intelligence": [],
                "context_summary": "No additional threat intelligence found from web sources.",
                "enhanced_threats": existing_threats
            }
        
        # LLM analyzes and contextualizes the intelligence
        # Optimize: Limit data for token efficiency
        threat_summary = [{'title': t.get('title', '')[:40], 'severity': t.get('severity', '')} for t in existing_threats[:3]]
        intel_summary = [{'source': i.get('source', ''), 'type': i.get('type', '')} for i in web_intel[:3]]
        
        context_prompt = f"""
        Threat analysis for {product_name}:
        
        CVE THREATS: {json.dumps(threat_summary)}
        WEB INTEL: {json.dumps(intel_summary)}
        
        JSON response:
        {{
            "context_summary": "Brief summary",
            "key_insights": ["insight1", "insight2"],
            "enhanced_recommendations": ["rec1", "rec2"]
        }}
        """
        
        try:
            response = await self.llm.generate(context_prompt, max_tokens=400)
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
            else:
                analysis = {"context_summary": "Analysis parsing failed"}
        except Exception as e:
            print(f"   Context analysis error: {e}")
            analysis = {"context_summary": "Failed to analyze web intelligence"}
        
        # Add existing NVD CVEs to web intelligence for processing
        print(f"   🔍 DEBUG: Found {len(existing_threats)} existing threats")
        for threat in existing_threats:
            print(f"   🔍 DEBUG: Threat source: {threat.get('source', 'Unknown')}")
            if threat.get('source') == 'NVD':
                print(f"   🔍 DEBUG: Adding NVD CVE to web intel: {threat.get('title', '')[:50]}")
                web_intel.append(threat)
        
        # Sort combined intelligence by recency
        from datetime import datetime
        
        def parse_intel_date(item):
            date_str = item.get('published', item.get('published_date', ''))
            if not date_str or date_str in ['Recent', 'Unknown']:
                return datetime.min
            try:
                for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d']:
                    try:
                        return datetime.strptime(date_str[:19], fmt[:10])
                    except:
                        continue
                return datetime.min
            except:
                return datetime.min
        
        # Combine and sort by recency (most recent first)
        combined_intel = sorted(existing_threats + web_intel, 
                              key=parse_intel_date, reverse=True)
        
        return {
            "web_intelligence": web_intel,
            "llm_analysis": analysis,
            "enhanced_threats": existing_threats,
            "combined_intelligence": combined_intel
        }
    
    async def enrich_threat_report(self, product_name: str, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Main method to enrich threats with web context"""
        print("🌐 Gathering web-based threat intelligence...")
        
        context_data = await self.gather_threat_context(product_name, threats)
        
        # Count intelligence sources
        intel_count = len(context_data.get("web_intelligence", []))
        print(f"   📊 Found {intel_count} additional intelligence sources")
        
        # Note: Threat verification integrated into smart filtering
        
        return context_data