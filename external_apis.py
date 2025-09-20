import aiohttp
import json
from typing import List, Dict, Any
from datetime import datetime, timedelta

class ExternalAPIs:
    """External threat intelligence API integrations"""
    
    def __init__(self):
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get_nvd_cves(self, keyword: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Get CVEs from NVD database"""
        
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': limit
        }
        
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            async with self.session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    data = await response.json()
                    cves = []
                    
                    for vuln in data.get('vulnerabilities', []):
                        cve_data = vuln.get('cve', {})
                        
                        # Extract CVSS score
                        cvss_score = 0.0
                        severity = "UNKNOWN"
                        
                        metrics = cve_data.get('metrics', {})
                        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        
                        # Extract description
                        descriptions = cve_data.get('descriptions', [])
                        description = "No description available"
                        for desc in descriptions:
                            if desc.get('lang') == 'en':
                                description = desc.get('value', '')[:200]
                                break
                        
                        cve_entry = {
                            'title': f"{cve_data.get('id', 'Unknown CVE')}: {description[:50]}...",
                            'description': description,
                            'severity': severity,
                            'cvss_score': cvss_score,
                            'cve_id': cve_data.get('id', 'Unknown'),
                            'published_date': cve_data.get('published', 'Unknown'),
                            'attack_vector': 'Network',  # Default assumption
                            'source': 'NVD'
                        }
                        
                        cves.append(cve_entry)
                    
                    return cves
                
        except Exception as e:
            print(f"   NVD API error: {e}")
        
        return []
    
    async def get_github_advisories(self, keyword: str, limit: int = 3) -> List[Dict[str, Any]]:
        """Get security advisories from GitHub"""
        
        url = "https://api.github.com/advisories"
        params = {
            'keyword': keyword,
            'per_page': limit,
            'sort': 'published',
            'direction': 'desc'
        }
        
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            async with self.session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    advisories = await response.json()
                    results = []
                    
                    for advisory in advisories:
                        result = {
                            'title': f"GitHub Advisory: {advisory.get('summary', 'Security Advisory')[:50]}...",
                            'description': advisory.get('description', '')[:200],
                            'severity': advisory.get('severity', 'MEDIUM').upper(),
                            'cvss_score': 0.0,  # GitHub doesn't always provide CVSS
                            'cve_id': advisory.get('cve_id', 'N/A'),
                            'published_date': advisory.get('published_at', 'Unknown'),
                            'attack_vector': 'Network',
                            'source': 'GitHub Security Advisory'
                        }
                        
                        # Estimate CVSS based on severity
                        severity_scores = {
                            'CRITICAL': 9.0,
                            'HIGH': 7.5,
                            'MEDIUM': 5.0,
                            'LOW': 2.5
                        }
                        result['cvss_score'] = severity_scores.get(result['severity'], 5.0)
                        
                        results.append(result)
                    
                    return results
                
        except Exception as e:
            print(f"   GitHub API error: {e}")
        
        return []
    
    async def search_exploit_db(self, keyword: str, limit: int = 3) -> List[Dict[str, Any]]:
        """Search Exploit Database (simplified)"""
        
        # Note: Exploit-DB doesn't have a public API, so this is a placeholder
        # In a real implementation, you might scrape their site or use Google Custom Search
        
        exploits = [
            {
                'title': f"Potential exploit for {keyword}",
                'description': f"Exploit targeting {keyword} vulnerabilities",
                'severity': 'HIGH',
                'cvss_score': 8.0,
                'cve_id': 'EDB-XXXX',
                'published_date': datetime.now().strftime('%Y-%m-%d'),
                'attack_vector': 'Network',
                'source': 'Exploit Database'
            }
        ]
        
        return exploits[:limit]
    
    async def gather_all_threats(self, keyword: str) -> List[Dict[str, Any]]:
        """Gather threats from all available sources"""
        
        all_threats = []
        
        print(f"   Fetching NVD CVEs for: {keyword}")
        nvd_threats = await self.get_nvd_cves(keyword, 3)
        all_threats.extend(nvd_threats)
        
        print(f"   Fetching GitHub advisories for: {keyword}")
        github_threats = await self.get_github_advisories(keyword, 2)
        all_threats.extend(github_threats)
        
        return all_threats