import json
import asyncio
from typing import List, Dict, Any
from agents.accuracy_enhancer import ThreatAccuracyEnhancer

class IntelligenceAgent:
    """Consolidated threat intelligence, context, and risk analysis agent"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.accuracy_enhancer = ThreatAccuracyEnhancer()
    
    async def comprehensive_analysis(self, product_info: Dict[str, Any]) -> Dict[str, Any]:
        """Single comprehensive analysis combining threat intel, context, and risk assessment"""
        
        try:
            # Extract keywords from product info
            keywords = self._extract_keywords(product_info)
            
            # Use LLM for threat intelligence gathering
            primary_keyword = keywords[0] if keywords else product_info.get('name', '')
            print(f"   Gathering comprehensive intelligence for: {primary_keyword}")
            
            # Generate threat intelligence using LLM
            threat_prompt = f"""
            Analyze security threats for: {primary_keyword}
            
            Provide a comprehensive threat analysis including:
            1. Known vulnerabilities (CVEs)
            2. Common attack vectors
            3. MITRE ATT&CK techniques
            4. Risk severity levels
            
            Format as JSON array with fields: title, description, severity, cve_id, cvss_score, mitre_technique
            """
            
            try:
                response = await self.llm.generate_response(threat_prompt)
                # Parse LLM response to extract threats
                all_threats = self._parse_llm_threats(response)
            except Exception as e:
                print(f"   LLM threat analysis failed: {e}")
                all_threats = []
            
            if not all_threats:
                print(f"   No threats found for {product_info.get('name', 'product')}")
                return {
                    'threats': [],
                    'risk_assessment': {'overall_risk_level': 'LOW', 'risk_score': 2.0},
                    'threat_context': {'context_summary': 'No threats identified'},
                    'mitre_mapping': [],
                    'validation_summary': 'No actionable intelligence found'
                }
            
            # Enhance threats with analyst-focused details
            enhanced_threats = self.accuracy_enhancer.enhance_threat_details(all_threats)
            
            print(f"   COMPREHENSIVE ANALYSIS: Found {len(enhanced_threats)} enhanced threats")
            
            # Return complete analysis with threat data
            return {
                'threats': enhanced_threats,
                'threat_context': {'context_summary': f'Analysis of {len(enhanced_threats)} threats identified'},
                'risk_assessment': self._create_fallback_risk_assessment(enhanced_threats),
                'mitre_mapping': [{'technique': 'T1190', 'tactic': 'Initial Access', 'description': 'Exploit Public-Facing Application'}],
                'validation_summary': {'relevance_score': 0.8, 'data_quality': 'high'},
                'analysis_method': 'LLM-based threat intelligence'
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
    
    def _parse_llm_threats(self, response: str) -> List[Dict[str, Any]]:
        """Parse LLM response to extract threat information"""
        try:
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                threats_data = json.loads(json_match.group())
                return threats_data
            else:
                # Fallback: create basic threat from text
                return [{
                    'title': 'General Security Threat',
                    'description': response[:200] + '...' if len(response) > 200 else response,
                    'severity': 'MEDIUM',
                    'cve_id': 'N/A',
                    'cvss_score': '5.0',
                    'mitre_technique': 'T1190'
                }]
        except Exception as e:
            print(f"   Failed to parse LLM response: {e}")
            return []