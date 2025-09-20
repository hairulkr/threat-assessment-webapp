import json
import asyncio
from typing import List, Dict, Any
from optimized_threat_intel import OptimizedThreatIntel
from agents.specialized_ranking_agents import MultiAgentRankingOrchestrator
from agents.accuracy_enhancer import ThreatAccuracyEnhancer

class ThreatIntelAgent:
    """Multi-agent optimized threat intelligence with enhanced accuracy for analysts"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.intel_sources = OptimizedThreatIntel()
        self.ranking_orchestrator = MultiAgentRankingOrchestrator()
        self.accuracy_enhancer = ThreatAccuracyEnhancer()
    
    async def fetch_recent_threats(self, product_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch real threat intelligence from external APIs"""
        
        # Extract keywords from product info
        keywords = self._extract_keywords(product_info)
        
        all_threats = []
        
        # Use optimized threat intelligence sources
        async with self.intel_sources as intel_client:
            # Use primary product name for optimized intelligence gathering
            primary_keyword = keywords[0] if keywords else product_info.get('name', '')
            print(f"   Gathering optimized threat intelligence for: {primary_keyword}")
            all_threats = await intel_client.gather_optimized_intel(primary_keyword)
        
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
            # Apply multi-agent ranking optimization
            print(f"   🤖 MULTI-AGENT RANKING: Optimizing {len(all_threats)} threats")
            ranking_result = await self.ranking_orchestrator.optimize_threat_ranking(all_threats, primary_keyword)
            
            optimized_threats = ranking_result['optimized_threats']
            metrics = ranking_result['optimization_metrics']
            breakdown = ranking_result['ranking_breakdown']
            
            # Enhance threats with analyst-focused details
            enhanced_threats = self.accuracy_enhancer.enhance_threat_details(optimized_threats)
            analyst_summary = self.accuracy_enhancer.generate_analyst_summary(enhanced_threats)
            
            print(f"   🎯 OPTIMIZED RESULTS: {len(enhanced_threats)} enhanced threats (score: {metrics['optimization_score']})")
            print(f"   🏢 CVE: {breakdown['cve_threats']} | 💥 Exploits: {breakdown['exploit_threats']} | 🔒 Relevant: {breakdown['relevant_threats']}")
            print(f"   ⚠️ ANALYST PRIORITY: {analyst_summary['threat_summary']['public_exploits']} public exploits, {analyst_summary['threat_summary']['easy_attacks']} easy attacks")
            
            return enhanced_threats
        
        print(f"   🔍 No threats found for {product_info.get('name', 'product')} - trying broader search")
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