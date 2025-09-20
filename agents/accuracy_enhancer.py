from typing import List, Dict, Any
import re

class ThreatAccuracyEnhancer:
    """Enhances threat analysis accuracy for security analysts"""
    
    def __init__(self):
        self.critical_keywords = [
            'remote code execution', 'rce', 'sql injection', 'xss', 'csrf',
            'authentication bypass', 'privilege escalation', 'buffer overflow',
            'deserialization', 'path traversal', 'xxe', 'ssrf'
        ]
    
    def enhance_threat_details(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance threat details with analyst-focused information"""
        enhanced_threats = []
        
        for threat in threats:
            enhanced = threat.copy()
            
            # Add exploit availability assessment
            enhanced['exploit_availability'] = self._assess_exploit_availability(threat)
            
            # Add patch status
            enhanced['patch_status'] = self._assess_patch_status(threat)
            
            # Add attack complexity
            enhanced['attack_complexity'] = self._assess_attack_complexity(threat)
            
            # Add business impact assessment
            enhanced['business_impact'] = self._assess_business_impact(threat)
            
            # Add detection difficulty
            enhanced['detection_difficulty'] = self._assess_detection_difficulty(threat)
            
            enhanced_threats.append(enhanced)
        
        return enhanced_threats
    
    def _assess_exploit_availability(self, threat: Dict[str, Any]) -> Dict[str, str]:
        """Assess exploit code availability"""
        title = threat.get('title', '').lower()
        description = threat.get('description', '').lower()
        source = threat.get('source', '').lower()
        
        if 'exploit database' in source or 'exploit-db' in source:
            return {'status': 'PUBLIC', 'confidence': 'HIGH', 'note': 'Exploit code publicly available'}
        elif '0day.today' in source:
            return {'status': 'LIKELY', 'confidence': 'MEDIUM', 'note': 'Zero-day marketplace listing'}
        elif any(keyword in title or keyword in description for keyword in ['exploit', 'poc', 'proof of concept']):
            return {'status': 'POSSIBLE', 'confidence': 'MEDIUM', 'note': 'Exploit references found'}
        else:
            return {'status': 'UNKNOWN', 'confidence': 'LOW', 'note': 'No exploit information available'}
    
    def _assess_patch_status(self, threat: Dict[str, Any]) -> Dict[str, str]:
        """Assess patch availability and status"""
        cve_id = threat.get('cve_id', '')
        published_date = threat.get('published_date', '')
        
        if cve_id and cve_id != 'N/A':
            # CVEs typically have patches within 30-90 days
            return {'status': 'LIKELY_AVAILABLE', 'confidence': 'MEDIUM', 'note': 'Check vendor security advisories'}
        elif 'github' in threat.get('source', '').lower():
            return {'status': 'LIKELY_AVAILABLE', 'confidence': 'HIGH', 'note': 'GitHub advisory suggests patch available'}
        else:
            return {'status': 'UNKNOWN', 'confidence': 'LOW', 'note': 'Patch status requires investigation'}
    
    def _assess_attack_complexity(self, threat: Dict[str, Any]) -> Dict[str, str]:
        """Assess attack complexity for threat prioritization"""
        title = threat.get('title', '').lower()
        description = threat.get('description', '').lower()
        cvss_score = threat.get('cvss_score', 0)
        
        # High CVSS with simple attack vectors
        if cvss_score >= 8.0 and any(simple in title or simple in description 
                                   for simple in ['remote', 'unauthenticated', 'network']):
            return {'level': 'LOW', 'note': 'High impact, easy to exploit'}
        elif cvss_score >= 7.0:
            return {'level': 'MEDIUM', 'note': 'Moderate complexity, significant impact'}
        elif cvss_score >= 4.0:
            return {'level': 'MEDIUM', 'note': 'Standard complexity attack'}
        else:
            return {'level': 'HIGH', 'note': 'Complex attack or low impact'}
    
    def _assess_business_impact(self, threat: Dict[str, Any]) -> Dict[str, str]:
        """Assess potential business impact"""
        title = threat.get('title', '').lower()
        description = threat.get('description', '').lower()
        severity = threat.get('severity', '').upper()
        
        if severity == 'CRITICAL' or any(critical in title or critical in description 
                                       for critical in self.critical_keywords):
            return {
                'level': 'CRITICAL',
                'areas': ['Data breach', 'Service disruption', 'Compliance violation'],
                'note': 'Immediate business risk'
            }
        elif severity == 'HIGH':
            return {
                'level': 'HIGH',
                'areas': ['Data exposure', 'System compromise'],
                'note': 'Significant business risk'
            }
        else:
            return {
                'level': 'MEDIUM',
                'areas': ['Limited exposure'],
                'note': 'Moderate business risk'
            }
    
    def _assess_detection_difficulty(self, threat: Dict[str, Any]) -> Dict[str, str]:
        """Assess how difficult this threat is to detect"""
        title = threat.get('title', '').lower()
        description = threat.get('description', '').lower()
        
        if any(stealthy in title or stealthy in description 
               for stealthy in ['memory', 'fileless', 'living off the land', 'bypass']):
            return {'level': 'HARD', 'note': 'Advanced detection methods required'}
        elif any(network in title or network in description 
                for network in ['network', 'remote', 'web']):
            return {'level': 'MEDIUM', 'note': 'Network monitoring can detect'}
        else:
            return {'level': 'EASY', 'note': 'Standard security tools can detect'}
    
    def generate_analyst_summary(self, enhanced_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate analyst-focused threat summary"""
        total_threats = len(enhanced_threats)
        
        # Categorize threats
        critical_threats = [t for t in enhanced_threats if t.get('severity') == 'CRITICAL']
        high_threats = [t for t in enhanced_threats if t.get('severity') == 'HIGH']
        
        # Exploit availability
        public_exploits = [t for t in enhanced_threats if t.get('exploit_availability', {}).get('status') == 'PUBLIC']
        
        # Attack complexity
        easy_attacks = [t for t in enhanced_threats if t.get('attack_complexity', {}).get('level') == 'LOW']
        
        return {
            'threat_summary': {
                'total_threats': total_threats,
                'critical_count': len(critical_threats),
                'high_count': len(high_threats),
                'public_exploits': len(public_exploits),
                'easy_attacks': len(easy_attacks)
            },
            'immediate_priorities': [
                t for t in enhanced_threats 
                if (t.get('severity') in ['CRITICAL', 'HIGH'] and 
                    t.get('exploit_availability', {}).get('status') in ['PUBLIC', 'LIKELY'])
            ][:5],
            'analyst_recommendations': self._generate_recommendations(enhanced_threats)
        }
    
    def _generate_recommendations(self, threats: List[Dict[str, Any]]) -> List[str]:
        """Generate specific recommendations for analysts"""
        recommendations = []
        
        # Check for public exploits
        public_exploits = [t for t in threats if t.get('exploit_availability', {}).get('status') == 'PUBLIC']
        if public_exploits:
            recommendations.append(f"URGENT: {len(public_exploits)} threats have public exploit code - prioritize patching")
        
        # Check for easy attacks
        easy_attacks = [t for t in threats if t.get('attack_complexity', {}).get('level') == 'LOW']
        if easy_attacks:
            recommendations.append(f"HIGH PRIORITY: {len(easy_attacks)} threats are easy to exploit - implement controls immediately")
        
        # Check for detection gaps
        hard_to_detect = [t for t in threats if t.get('detection_difficulty', {}).get('level') == 'HARD']
        if hard_to_detect:
            recommendations.append(f"DETECTION GAP: {len(hard_to_detect)} threats require advanced detection - enhance monitoring")
        
        return recommendations