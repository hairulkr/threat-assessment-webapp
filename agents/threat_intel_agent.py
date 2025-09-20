import json
import asyncio
from typing import List, Dict, Any
from external_apis import ExternalAPIs

class ThreatIntelAgent:
    """Real API-powered threat intelligence gathering"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.apis = ExternalAPIs()
    
    async def fetch_recent_threats(self, product_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch real threat intelligence from external APIs"""
        
        # Extract keywords from product info
        keywords = self._extract_keywords(product_info)
        
        all_threats = []
        
        # Run API calls in parallel for faster processing
        async with self.apis as api_client:
            tasks = []
            for keyword in keywords[:2]:  # Limit API calls
                print(f"   Searching threat databases for: {keyword}")
                tasks.append(api_client.gather_all_threats(keyword))
            
            # Execute all API calls concurrently
            if tasks:
                threat_results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in threat_results:
                    if isinstance(result, list):
                        all_threats.extend(result)
        
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
        
        if prioritized_threats:
            nvd_count = len([t for t in prioritized_threats if t.get('source') == 'NVD'])
            other_count = len(prioritized_threats) - nvd_count
            print(f"   Found {nvd_count} NVD CVEs and {other_count} other threats")
            if nvd_count == 0:
                print(f"   WARNING: No NVD CVEs found despite product having CVEs in database")
            return prioritized_threats[:3]  # Top 3 most recent threats
        
        print(f"   Found {len(all_threats)} total threats")
        return all_threats[:3]
    
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