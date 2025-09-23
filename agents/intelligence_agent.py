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
        
        # Comprehensive LLM analysis combining all aspects
        analysis_prompt = f"""
        Comprehensive threat analysis for {product_info.get('name', 'Product')}:
        
        THREAT INTELLIGENCE DATA:
        {json.dumps([{
            'cve_id': t.get('cve_id', 'N/A'),
            'title': t.get('title', '')[:60],
            'severity': t.get('severity', ''),
            'cvss_score': t.get('cvss_score', 0),
            'source': t.get('source', ''),
            'exploit_available': t.get('exploit_availability', {}).get('status', 'UNKNOWN')
        } for t in enhanced_threats[:8]], indent=2)}
        
        PRODUCT CONTEXT:
        {json.dumps(product_info, indent=2)}
        
        Provide comprehensive analysis with these sections:
        
        1. THREAT CONTEXT ANALYSIS:
           - Attack pattern correlation with historical campaigns
           - Threat actor attribution and TTPs
           - Geographic/industry targeting relevance
           - Campaign contextualization
        
        2. RISK ASSESSMENT:
           - Overall risk level: CRITICAL/HIGH/MEDIUM/LOW
           - Risk score: 1-10 scale
           - Business impact assessment
           - Attack vector analysis
           - Cascading risk evaluation
           - Likelihood and impact scores
        
        3. MITRE ATT&CK MAPPING:
           - Map each threat to appropriate MITRE techniques
           - Include tactic categories (Initial Access, Execution, etc.)
           - Provide technique descriptions
        
        4. VALIDATION SUMMARY:
           - Threat relevance to specific product
           - Coverage of critical attack vectors
           - Data quality assessment
        
        Return structured JSON:
        {{
            "threat_context": {{
                "attack_patterns": ["pattern1", "pattern2"],
                "threat_actors": ["actor1", "actor2"],
                "campaign_context": "description",
                "geographic_relevance": "assessment"
            }},
            "risk_assessment": {{
                "overall_risk_level": "HIGH",
                "risk_score": 8.5,
                "business_impact": "description",
                "attack_complexity": "LOW/MEDIUM/HIGH",
                "likelihood": "description",
                "cascading_risks": ["risk1", "risk2"]
            }},
            "mitre_mapping": [
                {{"technique": "T1190", "tactic": "Initial Access", "description": "Exploit Public-Facing Application"}},
                {{"technique": "T1059", "tactic": "Execution", "description": "Command and Scripting Interpreter"}}
            ],
            "validation_summary": {{
                "relevance_score": 0.9,
                "coverage_assessment": "comprehensive",
                "data_quality": "high",
                "missing_vectors": ["vector1", "vector2"]
            }}
        }}
        """
        
        try:
            response = await self.llm.generate(analysis_prompt, max_tokens=2000)
            
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                comprehensive_analysis = json.loads(json_match.group())
            else:
                # Fallback structured response
                comprehensive_analysis = self._create_fallback_analysis(enhanced_threats)
            
            print(f"   🎯 COMPREHENSIVE ANALYSIS: Risk level {comprehensive_analysis.get('risk_assessment', {}).get('overall_risk_level', 'UNKNOWN')}")
            
            # Return complete analysis with original threat data
            return {
                'threats': enhanced_threats,
                'threat_context': comprehensive_analysis.get('threat_context', {}),
                'risk_assessment': comprehensive_analysis.get('risk_assessment', {}),
                'mitre_mapping': comprehensive_analysis.get('mitre_mapping', []),
                'validation_summary': comprehensive_analysis.get('validation_summary', {}),
                'optimization_metrics': ranking_result['optimization_metrics']
            }
            
        except Exception as e:
            print(f"   Comprehensive analysis failed: {e}")
            return {
                'threats': enhanced_threats,
                'threat_context': {'context_summary': 'Analysis failed, using threat data only'},
                'risk_assessment': self._create_fallback_risk_assessment(enhanced_threats),
                'mitre_mapping': [{'technique': 'T1190', 'tactic': 'Initial Access', 'description': 'Exploit Public-Facing Application'}],
                'validation_summary': {'relevance_score': 0.7, 'data_quality': 'medium'}
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
    
    def _create_fallback_analysis(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create fallback analysis when LLM parsing fails"""
        severity_counts = {}
        for threat in threats:
            severity = threat.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Determine overall risk based on threat severity distribution
        if severity_counts.get('CRITICAL', 0) > 0:
            overall_risk = 'CRITICAL'
            risk_score = 9.0
        elif severity_counts.get('HIGH', 0) > 2:
            overall_risk = 'HIGH'
            risk_score = 8.0
        elif severity_counts.get('HIGH', 0) > 0 or severity_counts.get('MEDIUM', 0) > 3:
            overall_risk = 'MEDIUM'
            risk_score = 6.0
        else:
            overall_risk = 'LOW'
            risk_score = 4.0
        
        return {
            'threat_context': {
                'attack_patterns': ['Network-based attacks', 'Application vulnerabilities'],
                'context_summary': f'Analysis of {len(threats)} threats identified'
            },
            'risk_assessment': {
                'overall_risk_level': overall_risk,
                'risk_score': risk_score,
                'business_impact': f'{overall_risk} risk to business operations',
                'attack_complexity': 'MEDIUM'
            },
            'mitre_mapping': [
                {'technique': 'T1190', 'tactic': 'Initial Access', 'description': 'Exploit Public-Facing Application'},
                {'technique': 'T1059', 'tactic': 'Execution', 'description': 'Command and Scripting Interpreter'}
            ],
            'validation_summary': {
                'relevance_score': 0.8,
                'data_quality': 'medium',
                'coverage_assessment': 'basic'
            }
        }
    
    def _create_fallback_risk_assessment(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create fallback risk assessment"""
        return {
            'overall_risk_level': 'MEDIUM',
            'risk_score': 6.0,
            'business_impact': 'Potential system compromise and data exposure',
            'attack_complexity': 'MEDIUM',
            'likelihood': 'MEDIUM',
            'cascading_risks': ['Data breach', 'Service disruption']
        }