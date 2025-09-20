import json
import asyncio
from typing import List, Dict, Any
from threat_intel_sources import ThreatIntelSources

class ThreatIntelAgent:
    """Comprehensive threat intelligence gathering with 10+ sources"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.intel_sources = ThreatIntelSources()
    
    async def fetch_recent_threats(self, product_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch real threat intelligence from external APIs"""
        
        # Extract keywords from product info
        keywords = self._extract_keywords(product_info)
        
        all_threats = []
        
        # Use comprehensive threat intelligence sources
        async with self.intel_sources as intel_client:
            # Use primary product name for comprehensive intelligence gathering
            primary_keyword = keywords[0] if keywords else product_info.get('name', '')
            print(f"   Gathering comprehensive threat intelligence for: {primary_keyword}")
            all_threats = await intel_client.gather_all_intel(primary_keyword)
        
        # Sort all threats by publication date (most recent first)
        from datetime import datetime
        
        def parse_threat_date(threat):
            date_str = threat.get('published_date', threat.get('published', ''))
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
        
        # Sort by recency, then prioritize NVD CVEs for ties
        prioritized_threats = sorted(all_threats, key=lambda t: (
            parse_threat_date(t),
            1 if t.get('source') == 'NVD' else 0  # NVD gets priority for same dates
        ), reverse=True)
        
        if all_threats:
            # Threats are already filtered and prioritized by ThreatIntelSources
            official_count = len([t for t in all_threats if t.get('authority') == 'OFFICIAL'])
            verified_count = len([t for t in all_threats if t.get('authority') == 'VERIFIED'])
            community_count = len([t for t in all_threats if t.get('authority') == 'COMMUNITY'])
            
            print(f"   📊 FINAL RESULTS: {len(all_threats)} high-confidence threats")
            print(f"   🏢 Official: {official_count} | 🔒 Verified: {verified_count} | 👥 Community: {community_count}")
            
            return all_threats  # Already optimally filtered and limited
        
        print(f"   ⚠️ No relevant threats found for {product_info.get('name', 'product')}")
        return []
    
    def _extract_keywords(self, product_info: Dict[str, Any]) -> List[str]:
        keywords = [product_info.get('name', '').lower()]
        
        # Add technology keywords
        for tech in product_info.get('technologies', [])[:2]:
            keywords.append(tech.lower())
        
        # Add component keywords
        for comp in product_info.get('components', [])[:2]:
            if 'web' in comp:
                keywords.append('web application')
            elif 'database' in comp:
                keywords.append('sql')
        
        return [k for k in keywords if k and len(k) > 2][:3]