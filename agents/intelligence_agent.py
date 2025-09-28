"""LLM-driven threat intelligence with dynamic relevance ranking"""
import json
import asyncio
from typing import List, Dict, Any
from agents.optimized_threat_intel import OptimizedThreatIntel

class IntelligenceAgent:
    """LLM-driven threat intelligence with dynamic relevance ranking"""
    
    def __init__(self, llm_client, api_keys: Dict[str, str] = None):
        self.llm = llm_client
        self.api_keys = api_keys or {}
    
    async def gather_and_rank_threats(self, product_info: Dict[str, Any]) -> Dict[str, Any]:
        """Step 1: Gather threat intel and rank by relevance using LLM"""
        
        product_name = product_info.get('name', '')
        print(f"   🎯 Gathering threat intelligence for: {product_name}")
        
        # Get raw threat data from APIs + LLM
        raw_threats = await self._gather_raw_threats(product_name, product_info)
        
        if not raw_threats:
            return {'threats': [], 'risk_assessment': {'overall_risk_level': 'LOW', 'risk_score': 2.0}}
        
        # LLM-driven relevance ranking
        ranked_threats = await self._llm_relevance_ranking(raw_threats, product_info)
        
        # Generate risk assessment
        risk_assessment = await self._llm_risk_assessment(ranked_threats, product_info)
        
        print(f"   ✅ Ranked {len(ranked_threats)} threats by relevance")
        
        return {
            'threats': ranked_threats,
            'risk_assessment': risk_assessment,
            'analysis_method': 'LLM-driven relevance ranking',
            'sources_used': len(self.api_keys) if self.api_keys else 1
        }
    
    async def _gather_raw_threats(self, product_name: str, product_info: Dict[str, Any]) -> List[Dict]:
        """Gather raw threat data from APIs and LLM"""
        all_threats = []
        
        # Try API sources first
        if self.api_keys:
            try:
                async with OptimizedThreatIntel(self.api_keys) as threat_intel:
                    intel_data = await threat_intel.gather_intelligence(product_name, [product_name])
                    all_threats = self._process_intel_data(intel_data)
                    print(f"   📡 API intelligence: {len(all_threats)} threats from {intel_data.get('active_sources', 0)} sources")
            except Exception as e:
                print(f"   ⚠️ API intelligence failed: {e}")
        
        # LLM fallback with enhanced prompt
        if not all_threats:
            llm_threats = await self._llm_threat_generation(product_name, product_info)
            all_threats.extend(llm_threats)
        
        return all_threats[:15]  # Limit for processing
    
    async def _llm_threat_generation(self, product_name: str, product_info: Dict[str, Any]) -> List[Dict]:
        """LLM-generated threats with product context"""
        context = f"Product: {product_name}\nType: {product_info.get('type', 'software')}\nTechnologies: {', '.join(product_info.get('technologies', []))}"
        
        prompt = f"""Analyze security threats for this product:
{context}

Generate 8 realistic, specific threats in JSON format:
[{{
  "title": "Specific vulnerability name",
  "description": "Technical description with attack vector",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "cve_id": "CVE-YYYY-NNNN or POTENTIAL-YYYY-NNN",
  "cvss_score": "0.0-10.0",
  "mitre_technique": "T1XXX",
  "attack_vector": "NETWORK|ADJACENT|LOCAL|PHYSICAL",
  "exploit_complexity": "LOW|HIGH"
}}]

Focus on product-specific vulnerabilities. Return ONLY JSON array."""
        
        try:
            response = await self.llm.generate(prompt, max_tokens=2500)
            return self._parse_llm_threats(response)
        except Exception as e:
            print(f"   ⚠️ LLM threat generation failed: {e}")
            return self._create_fallback_threats(product_name)
    
    async def _llm_relevance_ranking(self, threats: List[Dict], product_info: Dict[str, Any]) -> List[Dict]:
        """LLM-driven threat relevance ranking"""
        if not threats:
            return []
        
        # Create threat summary for LLM
        threat_summaries = []
        for i, threat in enumerate(threats):
            summary = f"{i}: {threat.get('title', 'Unknown')} - {threat.get('severity', 'UNKNOWN')} - {threat.get('cve_id', 'N/A')}"
            threat_summaries.append(summary)
        
        prompt = f"""Rank these threats by relevance to {product_info.get('name', 'product')}:

{chr(10).join(threat_summaries)}

Consider:
- Product type and architecture
- Attack vector feasibility
- Business impact potential
- Exploit availability

Return comma-separated indices (most relevant first): 0,1,2,3..."""
        
        try:
            response = await self.llm.generate(prompt, max_tokens=200)
            indices = [int(x.strip()) for x in response.split(',') if x.strip().isdigit()]
            
            # Reorder threats by LLM ranking
            ranked_threats = []
            used_indices = set()
            
            for idx in indices:
                if 0 <= idx < len(threats) and idx not in used_indices:
                    threat = threats[idx].copy()
                    threat['relevance_rank'] = len(ranked_threats) + 1
                    ranked_threats.append(threat)
                    used_indices.add(idx)
            
            # Add remaining threats
            for i, threat in enumerate(threats):
                if i not in used_indices:
                    threat = threat.copy()
                    threat['relevance_rank'] = len(ranked_threats) + 1
                    ranked_threats.append(threat)
            
            return ranked_threats
            
        except Exception as e:
            print(f"   ⚠️ LLM ranking failed: {e}")
            # Fallback: rank by severity
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            return sorted(threats, key=lambda t: severity_order.get(t.get('severity', 'LOW'), 0), reverse=True)
    
    async def _llm_risk_assessment(self, threats: List[Dict], product_info: Dict[str, Any]) -> Dict[str, Any]:
        """LLM-driven risk assessment"""
        if not threats:
            return {'overall_risk_level': 'LOW', 'risk_score': 2.0}
        
        top_threats = threats[:5]
        threat_summary = '\n'.join([f"- {t.get('title', 'Unknown')} ({t.get('severity', 'UNKNOWN')})" for t in top_threats])
        
        prompt = f"""Assess overall risk for {product_info.get('name', 'product')} based on these top threats:

{threat_summary}

Return JSON:
{{
  "overall_risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "risk_score": 0.0-10.0,
  "key_concerns": ["concern1", "concern2"],
  "business_impact": "impact description"
}}

Return ONLY JSON."""
        
        try:
            response = await self.llm.generate(prompt, max_tokens=300)
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))
        except Exception as e:
            print(f"   ⚠️ Risk assessment failed: {e}")
        
        # Fallback risk calculation
        high_severity = sum(1 for t in threats if t.get('severity') in ['CRITICAL', 'HIGH'])
        if high_severity > 3:
            return {'overall_risk_level': 'HIGH', 'risk_score': 8.0}
        elif high_severity > 0:
            return {'overall_risk_level': 'MEDIUM', 'risk_score': 6.0}
        else:
            return {'overall_risk_level': 'LOW', 'risk_score': 4.0}
    
    def _process_intel_data(self, intel_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process real API intelligence data into threat format"""
        threats = []
        
        # Process NVD CVEs
        for cve in intel_data.get('nvd_cves', []):
            threats.append({
                'title': cve.get('description', '')[:100],
                'description': cve.get('description', ''),
                'severity': cve.get('severity', 'MEDIUM'),
                'cve_id': cve.get('cve_id', ''),
                'cvss_score': str(cve.get('cvss_score', 0)),
                'source': 'NVD API',
                'mitre_technique': 'T1190'
            })
        
        # Process CISA KEV
        for kev in intel_data.get('cisa_kev', []):
            threats.append({
                'title': kev.get('vulnerability_name', '')[:100],
                'description': f"{kev.get('vendor_project', '')} {kev.get('product', '')} vulnerability",
                'severity': 'HIGH',
                'cve_id': kev.get('cve_id', ''),
                'cvss_score': '8.0',
                'source': 'CISA KEV',
                'mitre_technique': 'T1190',
                'exploit_available': True
            })
        
        # Process CSE intelligence
        for cse_item in intel_data.get('cse_intelligence', []):
            threats.append({
                'title': cse_item.get('title', '')[:100],
                'description': cse_item.get('description', ''),
                'severity': cse_item.get('severity', 'MEDIUM'),
                'cve_id': cse_item.get('cve_id', ''),
                'cvss_score': str(cse_item.get('cvss_score', 6.0)),
                'source': cse_item.get('source', 'CSE'),
                'mitre_technique': 'T1190'
            })
        
        return threats[:20]
    
    def _parse_llm_threats(self, response: str) -> List[Dict[str, Any]]:
        """Parse LLM response to extract threat information"""
        try:
            import re
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                threats_data = json.loads(json_match.group())
                if threats_data and len(threats_data) > 0:
                    return threats_data
        except Exception as e:
            print(f"   JSON parsing failed: {e}")
        
        return []
    
    def _create_fallback_threats(self, product_name: str) -> List[Dict[str, Any]]:
        """Create fallback threats when LLM fails"""
        return [
            {
                'title': f'{product_name} Remote Code Execution',
                'description': f'Potential remote code execution vulnerability in {product_name}',
                'severity': 'HIGH',
                'cve_id': 'POTENTIAL-2024-001',
                'cvss_score': '8.5',
                'mitre_technique': 'T1190',
                'source': 'Fallback Analysis'
            },
            {
                'title': f'{product_name} Authentication Bypass',
                'description': f'Authentication bypass vulnerability in {product_name}',
                'severity': 'MEDIUM',
                'cve_id': 'POTENTIAL-2024-002',
                'cvss_score': '6.5',
                'mitre_technique': 'T1078',
                'source': 'Fallback Analysis'
            }
        ]