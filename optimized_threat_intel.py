import aiohttp
import asyncio
import feedparser
import json
import os
import streamlit as st
from typing import List, Dict, Any
from datetime import datetime, timedelta

class OptimizedThreatIntel:
    """Optimized threat intelligence with 5 core sources and smart filtering"""
    
    def __init__(self):
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get_nvd_cves(self, product_name: str) -> List[Dict[str, Any]]:
        """TIER 1: NVD CVE Database - Always include, no filtering"""
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {'keywordSearch': product_name, 'resultsPerPage': 5}
        
        try:
            async with self.session.get(url, params=params, timeout=10) as response:
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
                        
                        cves.append({
                            'title': f"{cve_data.get('id', 'Unknown CVE')}: {description[:50]}...",
                            'description': description,
                            'severity': severity,
                            'cvss_score': cvss_score,
                            'cve_id': cve_data.get('id', 'Unknown'),
                            'published_date': cve_data.get('published', 'Unknown'),
                            'source': 'NVD',
                            'authority': 'OFFICIAL',
                            'threat_level': severity,
                            'final_score': self.calculate_score(cvss_score, cve_data.get('published', ''), 3)
                        })
                    
                    return cves
        except Exception as e:
            print(f"   NVD error: {e}")
        return []
    
    async def get_github_advisories(self, product_name: str) -> List[Dict[str, Any]]:
        """TIER 1: GitHub Security Advisories - Verified source"""
        url = "https://api.github.com/advisories"
        params = {'keyword': product_name, 'per_page': 3, 'sort': 'published', 'direction': 'desc'}
        
        try:
            async with self.session.get(url, params=params, timeout=10) as response:
                if response.status == 200:
                    advisories = await response.json()
                    results = []
                    
                    for advisory in advisories:
                        severity = advisory.get('severity', 'MEDIUM').upper()
                        cvss_score = {'CRITICAL': 9.0, 'HIGH': 7.5, 'MEDIUM': 5.0, 'LOW': 2.5}.get(severity, 5.0)
                        
                        results.append({
                            'title': f"GitHub Advisory: {advisory.get('summary', 'Security Advisory')[:50]}...",
                            'description': advisory.get('description', '')[:200],
                            'severity': severity,
                            'cvss_score': cvss_score,
                            'cve_id': advisory.get('cve_id', 'N/A'),
                            'published_date': advisory.get('published_at', 'Unknown'),
                            'source': 'GitHub Security Advisory',
                            'authority': 'VERIFIED',
                            'threat_level': severity,
                            'final_score': self.calculate_score(cvss_score, advisory.get('published_at', ''), 2)
                        })
                    
                    return results
        except Exception as e:
            print(f"   GitHub error: {e}")
        return []
    
    async def get_cisa_alerts(self, product_name: str) -> List[Dict[str, Any]]:
        """TIER 1: CISA Alerts - Government authority"""
        try:
            feed = feedparser.parse('https://www.cisa.gov/cybersecurity-advisories/rss.xml')
            alerts = []
            
            for entry in feed.entries[:10]:
                title = getattr(entry, 'title', '')
                summary = getattr(entry, 'summary', '')
                content = f"{title} {summary}".lower()
                
                # Simple keyword matching
                if any(keyword in content for keyword in product_name.lower().split() if len(keyword) > 2):
                    alerts.append({
                        'title': title,
                        'description': summary[:200],
                        'severity': 'HIGH',
                        'cvss_score': 7.5,
                        'cve_id': 'N/A',
                        'published_date': getattr(entry, 'published', 'Recent'),
                        'source': 'CISA',
                        'authority': 'OFFICIAL',
                        'threat_level': 'HIGH',
                        'final_score': self.calculate_score(7.5, getattr(entry, 'published', ''), 3)
                    })
            
            return alerts[:2]
        except Exception:
            return []
    
    async def get_comprehensive_cse_intel(self, product_name: str) -> List[Dict[str, Any]]:
        """TIER 2: Comprehensive threat intelligence via Google CSE (12 sources)"""
        try:
            api_key = st.secrets.get("GOOGLE_API_KEY") or os.getenv('GOOGLE_API_KEY')
            search_engine_id = st.secrets.get("GOOGLE_CSE_ID") or os.getenv('GOOGLE_CSE_ID')
        except:
            api_key = os.getenv('GOOGLE_API_KEY')
            search_engine_id = os.getenv('GOOGLE_CSE_ID')
        
        if not api_key or not search_engine_id:
            print("   ⚠️ CSE credentials not found - skipping comprehensive search")
            return []
        
        # Search across all 12 configured sources
        search_query = f"{product_name} vulnerability exploit CVE"
        url = "https://www.googleapis.com/customsearch/v1"
        params = {'key': api_key, 'cx': search_engine_id, 'q': search_query, 'num': 5}
        
        try:
            async with self.session.get(url, params=params, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    intel_results = []
                    
                    for item in data.get('items', []):
                        # Determine source and authority from URL
                        url_lower = item.get('link', '').lower()
                        source_info = self.identify_source(url_lower)
                        
                        intel_results.append({
                            'title': item.get('title', 'Security Intelligence')[:80],
                            'description': item.get('snippet', '')[:200],
                            'severity': source_info['severity'],
                            'cvss_score': source_info['cvss_score'],
                            'cve_id': self.extract_cve_from_text(item.get('title', '') + ' ' + item.get('snippet', '')),
                            'published_date': 'Recent',
                            'source': source_info['source'],
                            'authority': source_info['authority'],
                            'threat_level': source_info['severity'],
                            'url': item.get('link', ''),
                            'final_score': self.calculate_score(source_info['cvss_score'], '', source_info['authority_weight'])
                        })
                    
                    print(f"   🔍 CSE SEARCH: Found {len(intel_results)} results across 12 sources")
                    return intel_results
                else:
                    print(f"   ❌ CSE API error: {response.status}")
        except Exception as e:
            print(f"   ❌ CSE error: {e}")
        return []
    
    def identify_source(self, url: str) -> Dict[str, Any]:
        """Identify source authority and scoring from URL"""
        if 'exploit-db.com' in url:
            return {'source': 'Exploit Database', 'authority': 'VERIFIED', 'authority_weight': 2, 'severity': 'CRITICAL', 'cvss_score': 9.0}
        elif 'cve.mitre.org' in url:
            return {'source': 'CVE MITRE', 'authority': 'OFFICIAL', 'authority_weight': 3, 'severity': 'HIGH', 'cvss_score': 8.0}
        elif 'nvd.nist.gov' in url:
            return {'source': 'NVD NIST', 'authority': 'OFFICIAL', 'authority_weight': 3, 'severity': 'HIGH', 'cvss_score': 8.0}
        elif 'vuldb.com' in url:
            return {'source': 'VulDB', 'authority': 'VERIFIED', 'authority_weight': 2, 'severity': 'HIGH', 'cvss_score': 7.5}
        elif 'securityfocus.com' in url:
            return {'source': 'SecurityFocus', 'authority': 'VERIFIED', 'authority_weight': 2, 'severity': 'HIGH', 'cvss_score': 7.0}
        elif 'cert.org' in url:
            return {'source': 'CERT', 'authority': 'OFFICIAL', 'authority_weight': 3, 'severity': 'HIGH', 'cvss_score': 7.5}
        elif 'security.adobe.com' in url:
            return {'source': 'Adobe Security', 'authority': 'OFFICIAL', 'authority_weight': 3, 'severity': 'HIGH', 'cvss_score': 7.0}
        elif 'support.apple.com' in url:
            return {'source': 'Apple Security', 'authority': 'OFFICIAL', 'authority_weight': 3, 'severity': 'HIGH', 'cvss_score': 7.0}
        elif '0day.today' in url:
            return {'source': '0day.today', 'authority': 'VERIFIED', 'authority_weight': 2, 'severity': 'CRITICAL', 'cvss_score': 8.5}
        elif 'bugcrowd.com' in url:
            return {'source': 'Bugcrowd', 'authority': 'VERIFIED', 'authority_weight': 2, 'severity': 'MEDIUM', 'cvss_score': 6.0}
        elif 'hackerone.com' in url:
            return {'source': 'HackerOne', 'authority': 'VERIFIED', 'authority_weight': 2, 'severity': 'MEDIUM', 'cvss_score': 6.0}
        elif 'rapid7.com' in url:
            return {'source': 'Rapid7', 'authority': 'VERIFIED', 'authority_weight': 2, 'severity': 'HIGH', 'cvss_score': 7.0}
        else:
            return {'source': 'Security Intelligence', 'authority': 'COMMUNITY', 'authority_weight': 1, 'severity': 'MEDIUM', 'cvss_score': 5.0}
    
    def extract_cve_from_text(self, text: str) -> str:
        """Extract CVE ID from text if present"""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        match = re.search(cve_pattern, text, re.IGNORECASE)
        return match.group(0) if match else 'N/A'
    
    async def get_microsoft_advisories(self, product_name: str) -> List[Dict[str, Any]]:
        """TIER 2: Microsoft Security Response Center"""
        try:
            feed = feedparser.parse('https://api.msrc.microsoft.com/cvrf/v2.0/updates')
            advisories = []
            
            for entry in feed.entries[:5]:
                title = getattr(entry, 'title', '')
                summary = getattr(entry, 'summary', '')
                content = f"{title} {summary}".lower()
                
                # Check for product relevance
                keywords = product_name.lower().split() + ['visual studio', 'microsoft', 'windows']
                if any(keyword in content for keyword in keywords if len(keyword) > 2):
                    advisories.append({
                        'title': title,
                        'description': summary[:200],
                        'severity': 'HIGH',
                        'cvss_score': 7.5,
                        'cve_id': 'N/A',
                        'published_date': getattr(entry, 'published', 'Recent'),
                        'source': 'Microsoft Security Response Center',
                        'authority': 'OFFICIAL',
                        'threat_level': 'HIGH',
                        'final_score': self.calculate_score(7.5, getattr(entry, 'published', ''), 3)
                    })
            
            return advisories[:2]
        except Exception:
            return []
    
    def calculate_score(self, cvss_score: float, published_date: str, authority_weight: int) -> float:
        """Simplified scoring: Authority × Recency × CVSS"""
        # Recency factor (1.0 for recent, 0.5 for old)
        recency = 1.0
        if published_date:
            try:
                pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                days_old = (datetime.now() - pub_date.replace(tzinfo=None)).days
                recency = max(0.5, 1.0 - (days_old / 365))  # Decay over 1 year
            except:
                recency = 0.8  # Default for unparseable dates
        
        # Normalize CVSS to 0-1 scale
        cvss_normalized = cvss_score / 10.0
        
        return authority_weight * recency * cvss_normalized
    
    def simple_relevance_check(self, item: Dict[str, Any], product_name: str) -> bool:
        """Simple relevance check - exact product name or major keywords"""
        title = item.get('title', '').lower()
        description = item.get('description', '').lower()
        product_lower = product_name.lower()
        
        # Exact product name match
        if product_lower in title or product_lower in description:
            return True
        
        # Major keywords (length > 3)
        keywords = [word for word in product_lower.split() if len(word) > 3]
        return any(keyword in title or keyword in description for keyword in keywords)
    
    async def gather_optimized_intel(self, product_name: str) -> List[Dict[str, Any]]:
        """Gather intelligence from 5 core sources with optimized filtering"""
        print(f"   🚀 OPTIMIZED INTEL: Gathering from 5 core sources for {product_name}")
        
        # Execute core sources in parallel (10-second timeout each)
        tasks = [
            self.get_nvd_cves(product_name),
            self.get_github_advisories(product_name),
            self.get_cisa_alerts(product_name),
            self.get_comprehensive_cse_intel(product_name),
            self.get_microsoft_advisories(product_name)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect all intelligence
        all_intel = []
        for result in results:
            if isinstance(result, list):
                all_intel.extend(result)
        
        # Apply simple relevance filtering
        relevant_intel = [item for item in all_intel if self.simple_relevance_check(item, product_name)]
        
        # Sort by final score (descending)
        relevant_intel.sort(key=lambda x: x.get('final_score', 0), reverse=True)
        
        # Categorize results
        official = [item for item in relevant_intel if item.get('authority') == 'OFFICIAL']
        verified = [item for item in relevant_intel if item.get('authority') == 'VERIFIED']
        
        print(f"   ✅ RESULTS: {len(relevant_intel)} relevant threats ({len(official)} official, {len(verified)} verified)")
        
        # Return top 8 threats
        return relevant_intel[:8]