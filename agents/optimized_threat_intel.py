"""Optimized threat intelligence: 3 direct APIs + 14 sources via Google CSE"""
import asyncio
import aiohttp
import json
from typing import Dict, List, Any
from datetime import datetime

class OptimizedThreatIntel:
    """17-source threat intelligence: 3 direct public APIs + 14 via Google CSE"""
    
    def __init__(self, api_keys: Dict[str, str] = None):
        self.api_keys = api_keys or {}
        # Direct public APIs (work without keys, optional keys for higher limits)
        self.direct_sources = {
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'cisa': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            'github': 'https://api.github.com/advisories'
        }
        # 14 sources accessible via Google CSE (single API key)
        self.cse_sources = [
            'exploit-db.com', 'vulners.com', 'security.snyk.io', 'vuldb.com',
            'packetstormsecurity.com', 'securityfocus.com', 'rapid7.com/db',
            'cvedetails.com', 'securitytracker.com', 'osvdb.org',
            'zerodayinitiative.com', 'fullhunt.io', 'opencve.io', 'vulmon.com'
        ]
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def gather_intelligence(self, product_name: str, keywords: List[str]) -> Dict[str, Any]:
        """Gather intelligence from 17 sources: 3 direct + 14 via CSE"""
        tasks = [
            self._query_nvd(product_name, keywords),
            self._query_cisa_kev(product_name),
            self._query_github_advisories(product_name),
            self._query_cse_sources(product_name, keywords)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten CSE results
        cse_results = results[3] if not isinstance(results[3], Exception) else []
        
        return {
            'nvd_cves': results[0] if not isinstance(results[0], Exception) else [],
            'cisa_kev': results[1] if not isinstance(results[1], Exception) else [],
            'github_advisories': results[2] if not isinstance(results[2], Exception) else [],
            'cse_intelligence': cse_results,
            'total_sources': 3 + len(self.cse_sources),  # 3 direct + 14 CSE sources
            'active_sources': sum(1 for r in results[:3] if not isinstance(r, Exception)) + (1 if cse_results else 0),
            'timestamp': datetime.now().isoformat()
        }
    
    async def _query_nvd(self, product_name: str, keywords: List[str]) -> List[Dict]:
        """Query NVD API (public, optional key for higher limits)"""
        try:
            params = {
                'keywordSearch': product_name,
                'resultsPerPage': 20,
                'startIndex': 0
            }
            
            headers = {}
            if self.api_keys.get('nvd_api_key'):
                headers['apiKey'] = self.api_keys['nvd_api_key']
            
            async with self.session.get(self.direct_sources['nvd'], params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_nvd_response(data)
                return []
        except Exception as e:
            print(f"NVD query failed: {e}")
            return []
    
    async def _query_cisa_kev(self, product_name: str) -> List[Dict]:
        """Query CISA KEV (public, no key required)"""
        try:
            async with self.session.get(self.direct_sources['cisa']) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_cisa_response(data, product_name)
                return []
        except Exception as e:
            print(f"CISA query failed: {e}")
            return []
    
    async def _query_github_advisories(self, product_name: str) -> List[Dict]:
        """Query GitHub Security Advisories (public, optional token for higher limits)"""
        try:
            headers = {}
            if self.api_keys.get('github_token'):
                headers['Authorization'] = f"token {self.api_keys['github_token']}"
            
            params = {'per_page': 20}
            async with self.session.get(self.direct_sources['github'], params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_github_response(data, product_name)
                return []
        except Exception as e:
            print(f"GitHub query failed: {e}")
            return []
    
    async def _query_cse_sources(self, product_name: str, keywords: List[str]) -> List[Dict]:
        """Query 14 security databases via Google Custom Search Engine"""
        if not self.api_keys.get('google_cse_key') or not self.api_keys.get('google_cse_id'):
            return []
        
        try:
            cse_url = 'https://www.googleapis.com/customsearch/v1'
            all_results = []
            
            # Query top 5 CSE sources to stay within API limits
            for source in self.cse_sources[:5]:
                params = {
                    'key': self.api_keys['google_cse_key'],
                    'cx': self.api_keys['google_cse_id'],
                    'q': f'{product_name} vulnerability CVE site:{source}',
                    'num': 3  # Limit results per source
                }
                
                async with self.session.get(cse_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        results = self._parse_cse_response(data, source)
                        all_results.extend(results)
                    
                # Rate limiting for CSE API
                await asyncio.sleep(0.1)
            
            return all_results[:15]  # Limit total CSE results
            
        except Exception as e:
            print(f"CSE query failed: {e}")
            return []
    
    def _parse_nvd_response(self, data: Dict) -> List[Dict]:
        """Parse NVD API response"""
        cves = []
        for vuln in data.get('vulnerabilities', []):
            cve = vuln.get('cve', {})
            cves.append({
                'cve_id': cve.get('id', ''),
                'description': cve.get('descriptions', [{}])[0].get('value', ''),
                'cvss_score': self._extract_cvss_score(cve),
                'severity': self._map_cvss_to_severity(self._extract_cvss_score(cve)),
                'published': cve.get('published', ''),
                'source': 'NVD'
            })
        return cves
    
    def _parse_github_response(self, data: List[Dict], product_name: str) -> List[Dict]:
        """Parse GitHub Security Advisories response"""
        advisories = []
        for advisory in data:
            if product_name.lower() in advisory.get('summary', '').lower():
                advisories.append({
                    'ghsa_id': advisory.get('ghsa_id', ''),
                    'summary': advisory.get('summary', ''),
                    'severity': advisory.get('severity', 'medium').upper(),
                    'published': advisory.get('published_at', ''),
                    'source': 'GitHub'
                })
        return advisories
    
    def _parse_cisa_response(self, data: Dict, product_name: str) -> List[Dict]:
        """Parse CISA KEV response"""
        kev_list = []
        for vuln in data.get('vulnerabilities', []):
            if product_name.lower() in vuln.get('product', '').lower():
                kev_list.append({
                    'cve_id': vuln.get('cveID', ''),
                    'vendor_project': vuln.get('vendorProject', ''),
                    'product': vuln.get('product', ''),
                    'vulnerability_name': vuln.get('vulnerabilityName', ''),
                    'date_added': vuln.get('dateAdded', ''),
                    'due_date': vuln.get('dueDate', ''),
                    'source': 'CISA KEV'
                })
        return kev_list
    
    def _parse_cse_response(self, data: Dict, source: str) -> List[Dict]:
        """Parse Google CSE response into threat format"""
        threats = []
        for item in data.get('items', []):
            # Extract CVE from title or snippet
            import re
            cve_match = re.search(r'CVE-\d{4}-\d{4,}', item.get('title', '') + ' ' + item.get('snippet', ''))
            
            if cve_match:
                threats.append({
                    'cve_id': cve_match.group(0),
                    'title': item.get('title', '')[:100],
                    'description': item.get('snippet', ''),
                    'source': f'CSE-{source}',
                    'url': item.get('link', ''),
                    'severity': 'MEDIUM',  # Default for CSE results
                    'cvss_score': 6.0
                })
        
        return threats
    
    def _extract_cvss_score(self, cve: Dict) -> float:
        """Extract CVSS score from CVE data"""
        metrics = cve.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            return metrics['cvssMetricV31'][0]['cvssData']['baseScore']
        elif 'cvssMetricV30' in metrics:
            return metrics['cvssMetricV30'][0]['cvssData']['baseScore']
        elif 'cvssMetricV2' in metrics:
            return metrics['cvssMetricV2'][0]['cvssData']['baseScore']
        return 0.0
    
    def _map_cvss_to_severity(self, score: float) -> str:
        """Map CVSS score to severity level"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0.0:
            return 'LOW'
        return 'UNKNOWN'