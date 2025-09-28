"""Specialized ranking agents for multi-agent threat prioritization"""
import asyncio
from typing import Dict, List, Any, Tuple
from datetime import datetime

class MultiAgentRankingOrchestrator:
    """Orchestrates multiple specialized ranking agents"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.agents = {
            'severity': SeverityRankingAgent(llm_client),
            'exploitability': ExploitabilityRankingAgent(llm_client),
            'business_impact': BusinessImpactRankingAgent(llm_client),
            'temporal': TemporalRankingAgent(llm_client)
        }
    
    async def rank_threats(self, threats: List[Dict], product_context: Dict) -> List[Dict]:
        """Multi-agent threat ranking with weighted consensus"""
        if not threats:
            return []
        
        # Get rankings from all agents
        rankings = {}
        for agent_name, agent in self.agents.items():
            try:
                rankings[agent_name] = await agent.rank_threats(threats, product_context)
            except Exception as e:
                print(f"Agent {agent_name} failed: {e}")
                rankings[agent_name] = list(range(len(threats)))
        
        # Calculate weighted consensus
        final_ranking = self._calculate_consensus(threats, rankings)
        
        # Apply final ranking
        ranked_threats = [threats[i] for i in final_ranking]
        
        # Add ranking metadata
        for i, threat in enumerate(ranked_threats):
            threat['final_rank'] = i + 1
            threat['ranking_confidence'] = self._calculate_confidence(i, rankings)
        
        return ranked_threats
    
    def _calculate_consensus(self, threats: List[Dict], rankings: Dict[str, List[int]]) -> List[int]:
        """Calculate weighted consensus ranking"""
        weights = {
            'severity': 0.35,
            'exploitability': 0.25,
            'business_impact': 0.25,
            'temporal': 0.15
        }
        
        threat_scores = {}
        for i in range(len(threats)):
            score = 0
            for agent_name, ranking in rankings.items():
                if i < len(ranking):
                    # Lower rank index = higher priority, so invert
                    normalized_score = (len(threats) - ranking.index(i)) / len(threats)
                    score += weights.get(agent_name, 0.25) * normalized_score
            threat_scores[i] = score
        
        # Sort by score (highest first)
        return sorted(threat_scores.keys(), key=lambda x: threat_scores[x], reverse=True)
    
    def _calculate_confidence(self, rank: int, rankings: Dict[str, List[int]]) -> float:
        """Calculate confidence score for ranking"""
        # Simplified confidence based on ranking consistency
        return max(0.5, 1.0 - (rank * 0.1))

class SeverityRankingAgent:
    """Ranks threats by severity and CVSS scores"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    async def rank_threats(self, threats: List[Dict], context: Dict) -> List[int]:
        """Rank by severity with CVSS weighting"""
        severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
        
        scored_threats = []
        for i, threat in enumerate(threats):
            severity_score = severity_map.get(threat.get('severity', 'UNKNOWN'), 0)
            cvss_score = float(threat.get('cvss_score', 0))
            
            # Combined score: severity level + normalized CVSS
            combined_score = severity_score * 2.5 + cvss_score
            scored_threats.append((i, combined_score))
        
        # Sort by score (highest first) and return indices
        scored_threats.sort(key=lambda x: x[1], reverse=True)
        return [i for i, _ in scored_threats]

class ExploitabilityRankingAgent:
    """Ranks threats by exploit availability and complexity"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    async def rank_threats(self, threats: List[Dict], context: Dict) -> List[int]:
        """Rank by exploitability factors"""
        scored_threats = []
        
        for i, threat in enumerate(threats):
            score = 0
            
            # Exploit availability
            if threat.get('exploit_available'):
                score += 5
            
            # Attack complexity (from CVSS)
            complexity = threat.get('attack_complexity', 'HIGH')
            if complexity == 'LOW':
                score += 3
            elif complexity == 'MEDIUM':
                score += 2
            
            # Network accessibility
            vector = threat.get('attack_vector', 'LOCAL')
            if vector == 'NETWORK':
                score += 4
            elif vector == 'ADJACENT':
                score += 2
            
            scored_threats.append((i, score))
        
        scored_threats.sort(key=lambda x: x[1], reverse=True)
        return [i for i, _ in scored_threats]

class BusinessImpactRankingAgent:
    """Ranks threats by business impact using LLM analysis"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    async def rank_threats(self, threats: List[Dict], context: Dict) -> List[int]:
        """Rank by business impact analysis"""
        if not threats:
            return []
        
        # Create business impact prompt
        threat_summaries = []
        for i, threat in enumerate(threats[:10]):  # Limit for LLM processing
            summary = f"{i}: {threat.get('cve_id', 'N/A')} - {threat.get('title', 'Unknown')[:50]}"
            threat_summaries.append(summary)
        
        prompt = f"""Analyze business impact for {context.get('product_name', 'product')}:

Threats:
{chr(10).join(threat_summaries)}

Rank by business impact (0=highest impact, 9=lowest):
Consider: data loss, service disruption, compliance, reputation.

Return only comma-separated indices: 0,1,2,3,4,5,6,7,8,9"""
        
        try:
            response = await asyncio.wait_for(
                self.llm.generate(prompt, max_tokens=100),
                timeout=30
            )
            
            # Parse LLM response
            indices = [int(x.strip()) for x in response.split(',') if x.strip().isdigit()]
            
            # Fill missing indices
            all_indices = set(range(len(threats)))
            missing = all_indices - set(indices)
            indices.extend(sorted(missing))
            
            return indices[:len(threats)]
            
        except Exception as e:
            print(f"Business impact ranking failed: {e}")
            return list(range(len(threats)))

class TemporalRankingAgent:
    """Ranks threats by temporal factors (age, patch availability)"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    async def rank_threats(self, threats: List[Dict], context: Dict) -> List[int]:
        """Rank by temporal urgency"""
        scored_threats = []
        current_time = datetime.now()
        
        for i, threat in enumerate(threats):
            score = 0
            
            # Age of vulnerability (newer = higher priority)
            published = threat.get('published', '')
            if published:
                try:
                    pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                    days_old = (current_time - pub_date).days
                    
                    if days_old < 30:
                        score += 5  # Very recent
                    elif days_old < 90:
                        score += 3  # Recent
                    elif days_old < 365:
                        score += 1  # Moderate age
                except:
                    pass
            
            # Patch status
            patch_status = threat.get('patch_status', 'unknown')
            if patch_status == 'no_patch':
                score += 4
            elif patch_status == 'patch_available':
                score += 1
            
            # CISA KEV listing (immediate priority)
            if threat.get('source') == 'CISA KEV':
                score += 6
            
            scored_threats.append((i, score))
        
        scored_threats.sort(key=lambda x: x[1], reverse=True)
        return [i for i, _ in scored_threats]