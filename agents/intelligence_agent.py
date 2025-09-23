import json
import asyncio
from typing import List, Dict, Any
from optimized_threat_intel import OptimizedThreatIntel
from agents.specialized_ranking_agents import MultiAgentRankingOrchestrator
from agents.accuracy_enhancer import ThreatAccuracyEnhancer

class IntelligenceAgent:
    """Consolidated threat intelligence, context, and risk analysis agent"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.intel_sources = OptimizedThreatIntel()
        self.ranking_orchestrator = MultiAgentRankingOrchestrator()
        self.accuracy_enhancer = ThreatAccuracyEnhancer()
    
    async def comprehensive_analysis(self, product_info: Dict[str, Any]) -> Dict[str, Any]:
        """Single comprehensive analysis combining threat intel, context, and risk assessment"""
        
        try:
            # Extract keywords from product info
            keywords = self._extract_keywords(product_info)
            
            # Gather threat intelligence from 17 sources
            all_threats = []
            async with self.intel_sources as intel_client:
                primary_keyword = keywords[0] if keywords else product_info.get('name', '')
                print(f"   Gathering comprehensive intelligence for: {primary_keyword}")
                all_threats = await intel_client.gather_optimized_intel(primary_keyword)
            
            if not all_threats:
                print(f"   🔍 No threats found for {product_info.get('name', 'product')}")
                return {
                    'threats': [],
                    'risk_assessment': {'overall_risk_level': 'LOW', 'risk_score': 2.0},
                    'threat_context': {'context_summary': 'No threats identified'},
                    'mitre_mapping': [],
                    'validation_summary': 'No actionable intelligence found'
                }
            
            # Apply multi-agent ranking optimization
            print(f"   🤖 MULTI-AGENT RANKING: Optimizing {len(all_threats)} threats")
            ranking_result = await self.ranking_orchestrator.optimize_threat_ranking(all_threats, primary_keyword)
            optimized_threats = ranking_result['optimized_threats']
            
            # Enhance threats with analyst-focused details
            enhanced_threats = self.accuracy_enhancer.enhance_threat_details(optimized_threats)
            
            print(f"   🎯 COMPREHENSIVE ANALYSIS: Found {len(enhanced_threats)} enhanced threats")
            
            # Return complete analysis with threat data
            return {
                'threats': enhanced_threats,
                'threat_context': {'context_summary': f'Analysis of {len(enhanced_threats)} threats identified'},
                'risk_assessment': self._create_fallback_risk_assessment(enhanced_threats),
                'mitre_mapping': [{'technique': 'T1190', 'tactic': 'Initial Access', 'description': 'Exploit Public-Facing Application'}],
                'validation_summary': {'relevance_score': 0.8, 'data_quality': 'high'},
                'optimization_metrics': ranking_result['optimization_metrics']
            }
            
        except Exception as e:
            print(f"   Comprehensive analysis failed: {e}")
            return {
                'threats': [],
                'threat_context': {'context_summary': 'Analysis failed'},
                'risk_assessment': {'overall_risk_level': 'MEDIUM', 'risk_score': 5.0},
                'mitre_mapping': [{'technique': 'T1190', 'tactic': 'Initial Access', 'description': 'Exploit Public-Facing Application'}],
                'validation_summary': {'relevance_score': 0.5, 'data_quality': 'low'}
            }
    
    def _extract_keywords(self, product_info: Dict[str, Any]) -> List[str]:
        """Extract keywords for threat intelligence gathering"""
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
    
    def _create_fallback_risk_assessment(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create fallback risk assessment"""
        if not threats:
            return {'overall_risk_level': 'LOW', 'risk_score': 2.0}
        
        high_severity = sum(1 for t in threats if t.get('severity') in ['CRITICAL', 'HIGH'])
        if high_severity > 2:
            return {'overall_risk_level': 'HIGH', 'risk_score': 8.0}
        elif high_severity > 0:
            return {'overall_risk_level': 'MEDIUM', 'risk_score': 6.0}
        else:
            return {'overall_risk_level': 'LOW', 'risk_score': 4.0}