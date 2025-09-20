import aiohttp
import asyncio
import feedparser
import json
import re
from typing import List, Dict, Any
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

class ThreatIntelSources:
    """Integration with multiple threat intelligence sources"""
    
    def __init__(self):
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get_github_advisories(self, product_name: str) -> List[Dict[str, Any]]:
        """Get latest security advisories from GitHub (last 30 days)"""
        thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        url = f"https://api.github.com/advisories?keyword={product_name.replace(' ', '+')}&published={thirty_days_ago}&per_page=3&sort=published&direction=desc"
        
        try:
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    advisories = []
                    for advisory in data:
                        advisories.append({
                            'source': 'GitHub Security Advisory',
                            'type': 'recent_advisory',
                            'title': advisory.get('summary', 'Security Advisory'),
                            'description': advisory.get('description', '')[:300],
                            'severity': advisory.get('severity', 'MEDIUM'),
                            'cve_id': advisory.get('cve_id', 'N/A'),
                            'published': advisory.get('published_at', 'Recent'),
                            'threat_level': advisory.get('severity', 'MEDIUM')
                        })
                    return advisories
        except Exception:
            pass
        
        return []
    
    async def get_shodan_intel(self, product_name: str) -> List[Dict[str, Any]]:
        """Get exposed services from Shodan (requires API key)"""
        import os
        api_key = os.getenv('SHODAN_API_KEY')
        if not api_key:
            return []
        
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={product_name}&limit=3"
        
        try:
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    results = []
                    for match in data.get('matches', [])[:3]:
                        results.append({
                            'source': 'Shodan',
                            'type': 'exposed_service',
                            'description': f"Exposed {product_name} service detected",
                            'ip': match.get('ip_str', 'N/A'),
                            'port': match.get('port', 'N/A'),
                            'country': match.get('location', {}).get('country_name', 'Unknown'),
                            'threat_level': 'HIGH'
                        })
                    return results
        except Exception:
            pass
        
        return []
    
    async def get_exploit_db_intel(self, product_name: str) -> List[Dict[str, Any]]:
        """Search Exploit Database for known exploits"""
        # Using Google search for Exploit-DB since they don't have a public API
        search_query = f"site:exploit-db.com {product_name} exploit"
        url = f"https://www.googleapis.com/customsearch/v1"
        
        import os
        api_key = os.getenv('GOOGLE_API_KEY')
        search_engine_id = os.getenv('GOOGLE_CSE_ID')
        
        if not api_key or not search_engine_id:
            return []
        
        params = {
            'key': api_key,
            'cx': search_engine_id,
            'q': search_query,
            'num': 3
        }
        
        try:
            async with self.session.get(url, params=params, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    exploits = []
                    for item in data.get('items', []):
                        exploits.append({
                            'source': 'Exploit Database',
                            'type': 'known_exploit',
                            'title': item.get('title', 'Exploit Found'),
                            'description': item.get('snippet', '')[:200],
                            'url': item.get('link', ''),
                            'threat_level': 'CRITICAL'
                        })
                    return exploits
        except Exception:
            pass
        
        return []
    
    async def get_otx_intel(self, product_name: str) -> List[Dict[str, Any]]:
        """Get threat intel from AlienVault OTX"""
        # Try multiple OTX endpoints for software products
        endpoints = [
            f"https://otx.alienvault.com/api/v1/search/pulses?q={product_name.replace(' ', '%20')}",
            f"https://otx.alienvault.com/api/v1/indicators/hostname/{product_name.replace(' ', '.')}/general"
        ]
        
        for url in endpoints:
            try:
                async with self.session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Handle search results
                        if 'results' in data and data['results']:
                            return [{
                                'source': 'AlienVault OTX',
                                'type': 'threat_pulse',
                                'description': f"Threat intelligence for {product_name}",
                                'threat_level': 'MEDIUM',
                                'pulses_found': len(data['results'])
                            }]
                        
                        # Handle indicator results
                        elif 'pulse_info' in data:
                            pulse_count = data.get('pulse_info', {}).get('count', 0)
                            if pulse_count > 0:
                                return [{
                                    'source': 'AlienVault OTX',
                                    'type': 'indicator_analysis',
                                    'description': f"Indicator analysis for {product_name}",
                                    'threat_level': 'HIGH' if pulse_count > 5 else 'MEDIUM',
                                    'pulses': pulse_count
                                }]
            except Exception:
                continue
        
        return []
    
    def get_security_feeds(self, product_name: str) -> List[Dict[str, Any]]:
        """Get latest security news from RSS feeds (last 7 days)"""
        feeds = [
            'https://krebsonsecurity.com/feed/',
            'https://www.schneier.com/feed/atom/',
            'https://threatpost.com/feed/',
            'https://www.cisa.gov/cybersecurity-advisories/rss.xml'
        ]
        
        seven_days_ago = datetime.now() - timedelta(days=7)
        intel = []
        
        for feed_url in feeds:
            try:
                feed = feedparser.parse(feed_url)
                for entry in feed.entries[:3]:
                    # Check publication date
                    pub_date = getattr(entry, 'published_parsed', None)
                    if pub_date:
                        entry_date = datetime(*pub_date[:6])
                        if entry_date < seven_days_ago:
                            continue
                    
                    title = getattr(entry, 'title', '')
                    summary = getattr(entry, 'summary', getattr(entry, 'description', ''))
                    content = f"{title} {summary}".lower()
                    
                    keywords = product_name.lower().replace('microsoft', '').replace('visual studio', 'vscode').split()
                    keywords.extend(['vscode', 'vs code', 'vulnerability', 'exploit'])
                    
                    if any(keyword in content for keyword in keywords if len(keyword) > 2):
                        intel.append({
                            'source': feed.feed.title if hasattr(feed.feed, 'title') else 'Security Feed',
                            'type': 'recent_news',
                            'title': title,
                            'description': summary[:300] if summary else 'No description available',
                            'url': getattr(entry, 'link', ''),
                            'published': getattr(entry, 'published', 'Recent'),
                            'threat_level': 'MEDIUM'
                        })
            except Exception:
                continue
        
        return intel[:3]
    
    async def get_cisa_alerts(self, product_name: str) -> List[Dict[str, Any]]:
        """Get latest CISA security alerts (last 14 days)"""
        try:
            feed = feedparser.parse('https://www.cisa.gov/cybersecurity-advisories/rss.xml')
            alerts = []
            fourteen_days_ago = datetime.now() - timedelta(days=14)
            
            for entry in feed.entries[:15]:
                pub_date = getattr(entry, 'published_parsed', None)
                if pub_date:
                    entry_date = datetime(*pub_date[:6])
                    if entry_date < fourteen_days_ago:
                        continue
                
                title = getattr(entry, 'title', '')
                summary = getattr(entry, 'summary', getattr(entry, 'description', ''))
                content = f"{title} {summary}".lower()
                
                if any(keyword in content for keyword in product_name.lower().split()):
                    alerts.append({
                        'source': 'CISA',
                        'type': 'recent_alert',
                        'title': title,
                        'description': summary[:300] if summary else 'No description available',
                        'url': getattr(entry, 'link', ''),
                        'published': getattr(entry, 'published', 'Recent'),
                        'threat_level': 'HIGH'
                    })
            
            return alerts[:2]
        except Exception:
            return []
    
    async def get_microsoft_advisories(self, product_name: str) -> List[Dict[str, Any]]:
        """Get Microsoft Security Response Center advisories"""
        try:
            feed = feedparser.parse('https://api.msrc.microsoft.com/cvrf/v2.0/updates')
            advisories = []
            thirty_days_ago = datetime.now() - timedelta(days=30)
            
            for entry in feed.entries[:10]:
                title = getattr(entry, 'title', '')
                summary = getattr(entry, 'summary', '')
                content = f"{title} {summary}".lower()
                
                # Check for product relevance
                keywords = product_name.lower().split() + ['visual studio', 'vscode', 'code', 'microsoft']
                if any(keyword in content for keyword in keywords if len(keyword) > 2):
                    advisories.append({
                        'source': 'Microsoft Security Response Center',
                        'type': 'vendor_advisory',
                        'title': title,
                        'description': summary[:300],
                        'url': getattr(entry, 'link', ''),
                        'published': getattr(entry, 'published', 'Recent'),
                        'threat_level': 'HIGH',
                        'authority': 'OFFICIAL'
                    })
            
            return advisories[:3]
        except Exception:
            return []
    
    async def get_google_security_blog(self, product_name: str) -> List[Dict[str, Any]]:
        """Get Google Security Blog posts"""
        try:
            feed = feedparser.parse('https://security.googleblog.com/feeds/posts/default')
            posts = []
            thirty_days_ago = datetime.now() - timedelta(days=30)
            
            for entry in feed.entries[:10]:
                pub_date = getattr(entry, 'published_parsed', None)
                if pub_date:
                    entry_date = datetime(*pub_date[:6])
                    if entry_date < thirty_days_ago:
                        continue
                
                title = getattr(entry, 'title', '')
                summary = getattr(entry, 'summary', '')
                content = f"{title} {summary}".lower()
                
                keywords = product_name.lower().split() + ['chrome', 'android', 'vulnerability']
                if any(keyword in content for keyword in keywords if len(keyword) > 2):
                    posts.append({
                        'source': 'Google Security Blog',
                        'type': 'vendor_research',
                        'title': title,
                        'description': summary[:300],
                        'url': getattr(entry, 'link', ''),
                        'published': getattr(entry, 'published', 'Recent'),
                        'threat_level': 'MEDIUM',
                        'authority': 'OFFICIAL'
                    })
            
            return posts[:2]
        except Exception:
            return []
    
    async def get_exploit_db_structured(self, product_name: str) -> List[Dict[str, Any]]:
        """Get structured exploit data from Exploit-DB"""
        try:
            # Search Exploit-DB CSV data
            url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
            async with self.session.get(url, timeout=15) as response:
                if response.status == 200:
                    csv_data = await response.text()
                    exploits = []
                    
                    # Parse CSV and find relevant exploits
                    lines = csv_data.split('\n')[1:50]  # Skip header, check first 50
                    for line in lines:
                        if not line.strip():
                            continue
                        
                        parts = line.split(',')
                        if len(parts) >= 3:
                            exploit_title = parts[2].lower() if len(parts) > 2 else ''
                            
                            # Check relevance
                            keywords = product_name.lower().split()
                            if any(keyword in exploit_title for keyword in keywords if len(keyword) > 2):
                                exploits.append({
                                    'source': 'Exploit Database (Structured)',
                                    'type': 'verified_exploit',
                                    'title': parts[2] if len(parts) > 2 else 'Exploit',
                                    'exploit_id': parts[0] if len(parts) > 0 else 'N/A',
                                    'platform': parts[1] if len(parts) > 1 else 'Unknown',
                                    'threat_level': 'CRITICAL',
                                    'authority': 'VERIFIED'
                                })
                    
                    return exploits[:3]
        except Exception:
            pass
        
        return []
    
    async def get_packet_storm_intel(self, product_name: str) -> List[Dict[str, Any]]:
        """Get latest security updates from Packet Storm"""
        try:
            feed = feedparser.parse('https://rss.packetstormsecurity.com/news/')
            intel = []
            seven_days_ago = datetime.now() - timedelta(days=7)
            
            for entry in feed.entries[:15]:
                pub_date = getattr(entry, 'published_parsed', None)
                if pub_date:
                    entry_date = datetime(*pub_date[:6])
                    if entry_date < seven_days_ago:
                        continue
                
                title = getattr(entry, 'title', '')
                summary = getattr(entry, 'summary', '')
                content = f"{title} {summary}".lower()
                
                keywords = product_name.lower().split() + ['vulnerability', 'exploit', 'security']
                if any(keyword in content for keyword in keywords if len(keyword) > 2):
                    intel.append({
                        'source': 'Packet Storm Security',
                        'type': 'security_update',
                        'title': title,
                        'description': summary[:300],
                        'url': getattr(entry, 'link', ''),
                        'published': getattr(entry, 'published', 'Recent'),
                        'threat_level': 'HIGH',
                        'authority': 'COMMUNITY'
                    })
            
            return intel[:2]
        except Exception:
            return []
    
    async def get_mitre_attack_updates(self, product_name: str) -> List[Dict[str, Any]]:
        """Get MITRE ATT&CK technique updates"""
        try:
            feed = feedparser.parse('https://attack.mitre.org/resources/updates/updates.xml')
            updates = []
            sixty_days_ago = datetime.now() - timedelta(days=60)
            
            for entry in feed.entries[:10]:
                pub_date = getattr(entry, 'published_parsed', None)
                if pub_date:
                    entry_date = datetime(*pub_date[:6])
                    if entry_date < sixty_days_ago:
                        continue
                
                title = getattr(entry, 'title', '')
                summary = getattr(entry, 'summary', '')
                content = f"{title} {summary}".lower()
                
                # Look for technique updates relevant to software products
                if any(term in content for term in ['technique', 'software', 'application', 'code']):
                    updates.append({
                        'source': 'MITRE ATT&CK',
                        'type': 'technique_update',
                        'title': title,
                        'description': summary[:300],
                        'url': getattr(entry, 'link', ''),
                        'published': getattr(entry, 'published', 'Recent'),
                        'threat_level': 'MEDIUM',
                        'authority': 'OFFICIAL'
                    })
            
            return updates[:2]
        except Exception:
            return []
    
    def calculate_relevance_score(self, item: Dict[str, Any], product_name: str) -> float:
        """Calculate relevance score (0-1) for threat intelligence item"""
        score = 0.0
        product_lower = product_name.lower()
        title = item.get('title', '').lower()
        description = item.get('description', '').lower()
        
        # Extract key product terms
        key_terms = []
        if 'jetbrains' in product_lower or 'intellij' in product_lower:
            key_terms = ['jetbrains', 'intellij', 'idea']
        elif 'visual studio' in product_lower or 'vscode' in product_lower:
            key_terms = ['visual', 'studio', 'vscode', 'microsoft']
        else:
            key_terms = product_lower.split()
        
        # Strict relevance check - require at least one key term
        has_key_term = any(term in title or term in description for term in key_terms if len(term) > 2)
        if not has_key_term:
            return 0.0  # Completely irrelevant
        
        # Exact product name match (highest relevance)
        if product_lower in title or product_lower in description:
            score += 0.5
        
        # Key terms match
        for term in key_terms:
            if len(term) > 2:
                if term in title:
                    score += 0.3
                elif term in description:
                    score += 0.15
        
        # Authority bonus
        authority = item.get('authority', 'COMMUNITY')
        if authority == 'OFFICIAL':
            score += 0.2
        elif authority == 'VERIFIED':
            score += 0.1
        
        return min(score, 1.0)  # Cap at 1.0
    
    def smart_filter_threats(self, all_intel: List[Dict[str, Any]], product_name: str) -> List[Dict[str, Any]]:
        """Enhanced filtering with relevance scoring for high confidence results"""
        
        # Calculate relevance scores
        for item in all_intel:
            # NVD CVEs are already product-specific, give them high relevance
            if item.get('source') == 'NVD' and item.get('cve_id', '').startswith('CVE-'):
                item['relevance_score'] = 0.8  # High relevance for actual CVEs
                print(f"   DEBUG: NVD CVE found with score 0.8")
            else:
                item['relevance_score'] = self.calculate_relevance_score(item, product_name)
        
        # Filter out low relevance items (0.4 threshold)
        relevant_intel = [item for item in all_intel if item['relevance_score'] >= 0.4]
        
        # Deduplicate by CVE or similar titles
        seen_cves = set()
        seen_titles = set()
        deduplicated = []
        
        for item in relevant_intel:
            cve_id = item.get('cve_id', '').upper()
            title_key = item.get('title', '').lower()[:50]
            
            if cve_id and cve_id != 'N/A' and cve_id in seen_cves:
                continue
            if title_key and title_key in seen_titles:
                continue
                
            deduplicated.append(item)
            if cve_id and cve_id != 'N/A':
                seen_cves.add(cve_id)
            if title_key:
                seen_titles.add(title_key)
        
        # Categorize by authority and threat level
        official_threats = [t for t in deduplicated if t.get('authority') == 'OFFICIAL']
        verified_threats = [t for t in deduplicated if t.get('authority') == 'VERIFIED']
        community_threats = [t for t in deduplicated if t.get('authority') == 'COMMUNITY']
        
        # Critical/High threats from any source
        critical_high = [t for t in deduplicated if t.get('threat_level') in ['CRITICAL', 'HIGH']]
        
        # Smart filtering with limits
        filtered_intel = []
        
        # TIER 1: All official sources (highest confidence)
        filtered_intel.extend(official_threats)
        
        # TIER 2: Top 5 verified sources by severity
        verified_sorted = sorted(verified_threats, 
                               key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x.get('threat_level', 'MEDIUM'), 2), 
                               reverse=True)
        filtered_intel.extend(verified_sorted[:5])
        
        # TIER 3: Top 3 community sources (most recent)
        community_sorted = sorted([t for t in community_threats if t not in filtered_intel], 
                                key=lambda x: x.get('published', ''), reverse=True)
        filtered_intel.extend(community_sorted[:3])
        
        # TIER 4: Ensure we have critical/high threats even if over limit
        for threat in critical_high:
            if threat not in filtered_intel and len(filtered_intel) < 20:
                filtered_intel.append(threat)
        
        # Sort by recency first, then relevance, authority, and threat level
        from datetime import datetime
        
        def parse_date(date_str):
            if not date_str or date_str in ['Recent', 'Unknown']:
                return datetime.min
            try:
                # Try multiple date formats
                for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d']:
                    try:
                        return datetime.strptime(date_str[:19], fmt[:10])
                    except:
                        continue
                return datetime.min
            except:
                return datetime.min
        
        authority_priority = {'OFFICIAL': 3, 'VERIFIED': 2, 'COMMUNITY': 1}
        threat_priority = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        
        filtered_intel.sort(key=lambda x: (
            parse_date(x.get('published', x.get('published_date', ''))),  # Most recent first
            x.get('relevance_score', 0),
            authority_priority.get(x.get('authority', 'COMMUNITY'), 1),
            threat_priority.get(x.get('threat_level', 'MEDIUM'), 2)
        ), reverse=True)
        
        return filtered_intel[:8]  # Focused on top threats
    
    async def gather_all_intel(self, product_name: str) -> List[Dict[str, Any]]:
        """Gather and intelligently filter threat intelligence for optimal LLM processing"""
        print(f"   🔍 Gathering enhanced threat intelligence for: {product_name}")
        
        all_intel = []
        
        # Run all intelligence gathering in parallel for faster processing
        print(f"   📋 Gathering intelligence from all sources in parallel...")
        
        # Create parallel tasks for all intelligence sources
        tasks = [
            # TIER 1: Official vendor sources
            self.get_microsoft_advisories(product_name),
            self.get_google_security_blog(product_name),
            # TIER 2: Government and verified sources  
            self.get_cisa_alerts(product_name),
            self.get_mitre_attack_updates(product_name),
            # TIER 3: Verified exploit databases
            self.get_exploit_db_structured(product_name),
            self.get_exploit_db_intel(product_name),
            # TIER 4: Community and research sources
            self.get_github_advisories(product_name),
            self.get_packet_storm_intel(product_name),
            self.get_otx_intel(product_name),
            # TIER 5: Exposure sources
            self.get_shodan_intel(product_name)
        ]
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect results from parallel execution
        for result in results:
            if isinstance(result, list):
                all_intel.extend(result)
        
        # Add synchronous feed intel
        feed_intel = self.get_security_feeds(product_name)
        all_intel.extend(feed_intel)
        
        # Apply smart filtering with relevance scoring
        print(f"   🧠 Applying relevance-based filtering for high confidence results...")
        raw_count = len(all_intel)
        filtered_intel = self.smart_filter_threats(all_intel, product_name)
        filtered_count = len(filtered_intel)
        
        # Calculate average relevance score
        avg_relevance = sum(item.get('relevance_score', 0) for item in filtered_intel) / max(filtered_count, 1)
        print(f"   📊 RELEVANCE QUALITY: Average score {avg_relevance:.2f}/1.0 (threshold: 0.4)")
        
        # Enhanced reporting with filtering stats
        official_sources = [item for item in filtered_intel if item.get('authority') == 'OFFICIAL']
        verified_sources = [item for item in filtered_intel if item.get('authority') == 'VERIFIED']
        community_sources = [item for item in filtered_intel if item.get('authority') == 'COMMUNITY']
        critical_high = [item for item in filtered_intel if item.get('threat_level') in ['CRITICAL', 'HIGH']]
        
        if official_sources:
            print(f"   ✅ OFFICIAL SOURCES: {len(official_sources)} authoritative advisories")
            for item in official_sources[:2]:
                print(f"      🏢 {item.get('source', 'Official')}: {item.get('title', 'Advisory')[:45]}...")
        
        if verified_sources:
            print(f"   🔒 VERIFIED SOURCES: {len(verified_sources)} confirmed exploits")
            for item in verified_sources[:2]:
                print(f"      ⚡ {item.get('source', 'Verified')}: {item.get('title', 'Exploit')[:45]}...")
        
        if community_sources:
            print(f"   👥 COMMUNITY SOURCES: {len(community_sources)} intelligence reports")
            for item in community_sources[:2]:
                print(f"      📊 {item.get('source', 'Community')}: {item.get('title', 'Report')[:45]}...")
        
        if critical_high:
            print(f"   🚨 HIGH PRIORITY: {len(critical_high)} critical/high severity threats")
        
        print(f"   🎯 SMART FILTERING: {raw_count} raw → {filtered_count} filtered (relevance ≥ 0.4)")
        print(f"   📈 FINAL INTELLIGENCE: {filtered_count} high-confidence sources ({len(official_sources)} official, {len(verified_sources)} verified, {len(community_sources)} community)")
        
        # Ensure minimum confidence by adding fallback intelligence if needed
        if filtered_count == 0:
            print(f"   ⚠️  No specific threats found, adding general security intelligence...")
            filtered_intel = [{
                'source': 'General Security Intelligence',
                'type': 'baseline_assessment',
                'title': f'General security assessment for {product_name}',
                'description': f'Baseline security considerations and common vulnerabilities for {product_name} type applications',
                'threat_level': 'MEDIUM',
                'authority': 'COMMUNITY'
            }]
        
        return filtered_intel