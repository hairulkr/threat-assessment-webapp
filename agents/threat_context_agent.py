import json
from typing import List, Dict, Any
from threat_intel_sources import ThreatIntelSources

class ThreatContextAgent:
    """Enhanced threat intelligence with web context"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    async def gather_threat_context(self, product_name: str, existing_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Gather additional threat context from multiple sources"""
        
        # Get threat intelligence from external sources
        async with ThreatIntelSources() as intel_sources:
            web_intel = await intel_sources.gather_all_intel(product_name)
        
        if not web_intel:
            return {
                "web_intelligence": [],
                "context_summary": "No additional threat intelligence found from web sources.",
                "enhanced_threats": existing_threats
            }
        
        # LLM analyzes and contextualizes the intelligence
        context_prompt = f"""
        Analyze this threat intelligence for {product_name}:
        
        EXISTING CVE THREATS:
        {json.dumps(existing_threats, indent=2)}
        
        WEB INTELLIGENCE:
        {json.dumps(web_intel, indent=2)}
        
        Provide analysis in JSON format:
        {{
            "context_summary": "Brief summary of additional threats found",
            "key_insights": ["insight1", "insight2", "insight3"],
            "threat_trends": "Current threat landscape trends",
            "enhanced_recommendations": ["rec1", "rec2", "rec3"]
        }}
        """
        
        try:
            response = await self.llm.generate(context_prompt, max_tokens=600)
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