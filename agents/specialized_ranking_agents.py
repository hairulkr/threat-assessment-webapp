import asyncio
from typing import List, Dict, Any, Tuple
from datetime import datetime, timedelta

class CVERankingAgent:
    """Specialized agent for CVE-based threat ranking"""
    
    def __init__(self):
        self.weight_multiplier = 1.5  # CVEs get priority
    
    def rank_cve_threats(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank CVE threats using specialized CVE scoring"""
        cve_threats = [t for t in threats if t.get('cve_id', 'N/A') != 'N/A']
        
        for threat in cve_threats:
            # CVE-specific scoring factors
            cvss_score = threat.get('cvss_score', 0)
            severity = threat.get('severity', 'UNKNOWN')
            
            # CVE recency bonus (CVEs decay slower)
            recency_factor = self._calculate_cve_recency(threat.get('published_date', ''))
            
            # CVSS severity multipliers
            severity_multiplier = {
                'CRITICAL': 1.0, 'HIGH': 0.85, 'MEDIUM': 0.6, 'LOW': 0.3
            }.get(severity, 0.5)
            
            # Calculate specialized CVE score
            threat['cve_rank_score'] = (cvss_score * severity_multiplier * recency_factor * self.weight_multiplier)
        
        return sorted(cve_threats, key=lambda x: x.get('cve_rank_score', 0), reverse=True)
    
    def _calculate_cve_recency(self, published_date: str) -> float:
        """CVE-specific recency calculation (slower decay)"""
        if not published_date or published_date in ['Recent', 'Unknown']:
            return 0.8
        
        try:
            pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
            days_old = (datetime.now() - pub_date.replace(tzinfo=None)).days
            # CVEs decay over 2 years instead of 1
            return max(0.3, 1.0 - (days_old / 730))
        except:
            return 0.7

class ExploitRankingAgent:
    """Specialized agent for exploit-based threat ranking"""
    
    def __init__(self):
        self.exploit_sources = ['Exploit Database', '0day.today', 'Rapid7']
    
    def rank_exploit_threats(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank exploit threats using exploit-specific factors"""
        exploit_threats = [t for t in threats if t.get('source') in self.exploit_sources]
        
        for threat in exploit_threats:
            # Exploit-specific scoring
            base_score = threat.get('cvss_score', 5.0)
            source = threat.get('source', '')
            
            # Source reliability multipliers
            source_multiplier = {
                'Exploit Database': 1.2,  # Most reliable
                '0day.today': 1.1,        # High value but newer
                'Rapid7': 1.0             # Commercial but verified
            }.get(source, 0.8)
            
            # Exploit availability bonus (immediate threat)
            exploit_bonus = 2.0 if 'exploit' in threat.get('title', '').lower() else 1.0
            
            threat['exploit_rank_score'] = base_score * source_multiplier * exploit_bonus
        
        return sorted(exploit_threats, key=lambda x: x.get('exploit_rank_score', 0), reverse=True)

class AuthorityRankingAgent:
    """Specialized agent for authority-based ranking"""
    
    def __init__(self):
        self.authority_weights = {'OFFICIAL': 3.0, 'VERIFIED': 2.0, 'COMMUNITY': 1.0}
    
    def rank_by_authority(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank threats by source authority and credibility"""
        for threat in threats:
            authority = threat.get('authority', 'COMMUNITY')
            source = threat.get('source', '')
            
            # Base authority weight
            auth_weight = self.authority_weights.get(authority, 1.0)
            
            # Government/Official source bonuses
            if any(gov in source.lower() for gov in ['cisa', 'cert', 'nist', 'nvd']):
                auth_weight *= 1.3
            
            # Vendor-specific bonuses
            elif any(vendor in source.lower() for vendor in ['microsoft', 'adobe', 'apple']):
                auth_weight *= 1.2
            
            threat['authority_rank_score'] = threat.get('cvss_score', 5.0) * auth_weight
        
        return sorted(threats, key=lambda x: x.get('authority_rank_score', 0), reverse=True)

class RelevanceRankingAgent:
    """Specialized agent for product relevance ranking"""
    
    def __init__(self):
        self.relevance_threshold = 0.4
    
    def rank_by_relevance(self, threats: List[Dict[str, Any]], product_name: str) -> List[Dict[str, Any]]:
        """Rank threats by product-specific relevance"""
        product_keywords = set(product_name.lower().split())
        
        for threat in threats:
            title = threat.get('title', '').lower()
            description = threat.get('description', '').lower()
            
            # Calculate keyword overlap
            title_words = set(title.split())
            desc_words = set(description.split())
            
            # Exact product name match gets highest score
            if product_name.lower() in title or product_name.lower() in description:
                relevance_score = 1.0
            else:
                # Keyword overlap scoring
                title_overlap = len(product_keywords.intersection(title_words)) / max(len(product_keywords), 1)
                desc_overlap = len(product_keywords.intersection(desc_words)) / max(len(product_keywords), 1)
                relevance_score = max(title_overlap, desc_overlap * 0.7)  # Title weighted higher
            
            threat['relevance_score'] = relevance_score
            threat['relevance_rank_score'] = threat.get('cvss_score', 5.0) * (1 + relevance_score)
        
        # Filter by relevance threshold and sort
        relevant_threats = [t for t in threats if t.get('relevance_score', 0) >= self.relevance_threshold]
        return sorted(relevant_threats, key=lambda x: x.get('relevance_rank_score', 0), reverse=True)

class MultiAgentRankingOrchestrator:
    """Orchestrates multiple ranking agents for optimized threat prioritization"""
    
    def __init__(self):
        self.cve_agent = CVERankingAgent()
        self.exploit_agent = ExploitRankingAgent()
        self.authority_agent = AuthorityRankingAgent()
        self.relevance_agent = RelevanceRankingAgent()
    
    async def optimize_threat_ranking(self, threats: List[Dict[str, Any]], product_name: str) -> Dict[str, Any]:
        """Multi-agent threat ranking optimization"""
        
        # Parallel agent processing
        tasks = [
            asyncio.create_task(self._run_cve_ranking(threats)),
            asyncio.create_task(self._run_exploit_ranking(threats)),
            asyncio.create_task(self._run_authority_ranking(threats)),
            asyncio.create_task(self._run_relevance_ranking(threats, product_name))
        ]
        
        results = await asyncio.gather(*tasks)
        cve_ranked, exploit_ranked, authority_ranked, relevance_ranked = results
        
        # Aggregate rankings using weighted ensemble
        final_ranking = self._ensemble_ranking(
            threats, cve_ranked, exploit_ranked, authority_ranked, relevance_ranked
        )
        
        return {
            'optimized_threats': final_ranking[:12],  # Increased to 12 for comprehensive analysis
            'ranking_breakdown': {
                'cve_threats': len(cve_ranked),
                'exploit_threats': len(exploit_ranked),
                'high_authority': len([t for t in authority_ranked if t.get('authority') == 'OFFICIAL']),
                'relevant_threats': len(relevance_ranked)
            },
            'optimization_metrics': self._calculate_optimization_metrics(final_ranking)
        }
    
    async def _run_cve_ranking(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run CVE ranking agent"""
        return self.cve_agent.rank_cve_threats(threats)
    
    async def _run_exploit_ranking(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run exploit ranking agent"""
        return self.exploit_agent.rank_exploit_threats(threats)
    
    async def _run_authority_ranking(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run authority ranking agent"""
        return self.authority_agent.rank_by_authority(threats)
    
    async def _run_relevance_ranking(self, threats: List[Dict[str, Any]], product_name: str) -> List[Dict[str, Any]]:
        """Run relevance ranking agent"""
        return self.relevance_agent.rank_by_relevance(threats, product_name)
    
    def _ensemble_ranking(self, original_threats: List[Dict[str, Any]], *ranked_lists) -> List[Dict[str, Any]]:
        """Combine rankings using weighted ensemble method"""
        threat_scores = {}
        
        # Initialize with original threats
        for threat in original_threats:
            threat_id = threat.get('cve_id', threat.get('title', ''))
            threat_scores[threat_id] = {
                'threat': threat,
                'scores': [],
                'weights': []
            }
        
        # Collect scores from each agent
        agent_weights = [1.5, 1.2, 1.3, 1.4]  # CVE, Exploit, Authority, Relevance
        
        for i, ranked_list in enumerate(ranked_lists):
            weight = agent_weights[i]
            
            for j, threat in enumerate(ranked_list):
                threat_id = threat.get('cve_id', threat.get('title', ''))
                if threat_id in threat_scores:
                    # Position-based scoring (higher position = higher score)
                    position_score = (len(ranked_list) - j) / len(ranked_list)
                    threat_scores[threat_id]['scores'].append(position_score)
                    threat_scores[threat_id]['weights'].append(weight)
        
        # Calculate weighted ensemble scores
        final_threats = []
        for threat_id, data in threat_scores.items():
            if data['scores']:
                weighted_score = sum(s * w for s, w in zip(data['scores'], data['weights'])) / sum(data['weights'])
                threat = data['threat'].copy()
                threat['ensemble_score'] = weighted_score
                final_threats.append(threat)
        
        return sorted(final_threats, key=lambda x: x.get('ensemble_score', 0), reverse=True)
    
    def _calculate_optimization_metrics(self, final_ranking: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate optimization performance metrics"""
        if not final_ranking:
            return {'optimization_score': 0, 'coverage_score': 0, 'diversity_score': 0}
        
        # Coverage: How many different sources/authorities
        sources = set(t.get('source', '') for t in final_ranking)
        authorities = set(t.get('authority', '') for t in final_ranking)
        
        # Diversity: CVSS score distribution
        cvss_scores = [t.get('cvss_score', 0) for t in final_ranking]
        cvss_variance = sum((s - sum(cvss_scores)/len(cvss_scores))**2 for s in cvss_scores) / len(cvss_scores)
        
        return {
            'optimization_score': round(sum(t.get('ensemble_score', 0) for t in final_ranking) / len(final_ranking), 2),
            'coverage_score': len(sources) + len(authorities),
            'diversity_score': round(cvss_variance, 2),
            'source_diversity': len(sources),
            'authority_diversity': len(authorities)
        }