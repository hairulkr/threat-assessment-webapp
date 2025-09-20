import json
import aiohttp
import urllib.parse
from typing import Dict, Any, List
import re

class ProductInfoAgent:
    """LLM-powered product information gathering with smart completion"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    async def search_cpe_products(self, query: str) -> List[Dict[str, Any]]:
        """Search CPE database for exact product names with CVE counts"""
        encoded_query = urllib.parse.quote_plus(query)
        url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={encoded_query}&resultsPerPage=15"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    data = await response.json()
                    products = []
                    seen_names = set()
                    
                    for product in data.get("products", []):
                        cpe_name = product.get("cpe", {}).get("cpeName", "")
                        if cpe_name:
                            parts = cpe_name.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3].replace("_", " ").title()
                                product_name = parts[4].replace("_", " ").title()
                                
                                # Create clean product name
                                if vendor.lower() in product_name.lower():
                                    clean_name = product_name
                                else:
                                    clean_name = f"{vendor} {product_name}"
                                
                                if clean_name not in seen_names and len(clean_name) > 2:
                                    seen_names.add(clean_name)
                                    products.append({
                                        "name": clean_name,
                                        "cpe": cpe_name,
                                        "vendor": vendor,
                                        "product": product_name
                                    })
                    
                    return products[:8]
        except Exception as e:
            print(f"CPE search error: {e}")
            return []
    
    async def get_product_suggestions(self, user_input: str) -> List[Dict[str, Any]]:
        """Get comprehensive product suggestions from multiple sources"""
        suggestions = []
        
        # 1. Get CPE database matches (most accurate)
        cpe_products = await self.search_cpe_products(user_input)
        for product in cpe_products:
            suggestions.append({
                'name': product['name'],
                'source': 'NVD CPE Database',
                'confidence': 'High',
                'cpe': product.get('cpe', '')
            })
        
        # 2. Get LLM smart completions (broader coverage)
        llm_suggestions = await self.smart_product_completion(user_input)
        for suggestion in llm_suggestions:
            # Avoid duplicates
            if not any(s['name'].lower() == suggestion.lower() for s in suggestions):
                suggestions.append({
                    'name': suggestion,
                    'source': 'AI Completion',
                    'confidence': 'Medium'
                })
        
        # 3. Test CVE availability for top suggestions
        for suggestion in suggestions[:5]:
            cve_test = await self.test_cve_availability(suggestion['name'])
            suggestion['has_cves'] = cve_test.get('has_cves', False)
            suggestion['cve_count'] = cve_test.get('total_cves', 0)
            if suggestion['has_cves']:
                suggestion['confidence'] = 'High'
        
        # Sort by confidence and CVE availability
        suggestions.sort(key=lambda x: (
            x.get('has_cves', False),
            x.get('cve_count', 0),
            x['confidence'] == 'High'
        ), reverse=True)
        
        return suggestions[:8]
    
    async def test_cve_availability(self, product_name: str) -> Dict[str, Any]:
        """Test if product has CVEs available"""
        encoded_product = urllib.parse.quote_plus(product_name)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_product}&resultsPerPage=1"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as response:
                    if response.status == 200:
                        data = await response.json()
                        total_results = data.get("totalResults", 0)
                        
                        return {
                            "product": product_name,
                            "has_cves": total_results > 0,
                            "total_cves": total_results,
                            "sample_cve": data.get("vulnerabilities", [{}])[0].get("cve", {}).get("id", "N/A") if total_results > 0 else None
                        }
                    else:
                        return {"product": product_name, "has_cves": False, "total_cves": 0}
        except Exception as e:
            return {
                "product": product_name,
                "has_cves": False,
                "total_cves": 0,
                "error": str(e)
            }
    
    async def smart_product_completion(self, user_input: str) -> List[str]:
        """Enhanced smart product completion using LLM with latest software knowledge"""
        if len(user_input) < 2:
            return []
        
        prompt = f"""
        User input: "{user_input}"
        
        Complete this with current, widely-used software products that are actively maintained and commonly deployed. Focus on latest versions and popular solutions with known security vulnerabilities.
        Return JSON array (1 result if exact, multiple if incomplete):
        ["product1", "product2", ...]
        
        Examples:
        - "visual" -> ["Visual Studio Code", "Visual Studio 2022", "Visual Studio Community"]
        - "apache" -> ["Apache Tomcat", "Apache HTTP Server", "Apache Kafka", "Apache Struts"]
        - "docker" -> ["Docker Desktop", "Docker Engine", "Docker Compose"]
        - "node" -> ["Node.js", "NodeJS", "Node.js Runtime"]
        - "python" -> ["Python", "Python 3.x", "CPython"]
        - "react" -> ["React", "React Native", "ReactJS"]
        - "spring" -> ["Spring Framework", "Spring Boot", "Spring Security"]
        - "jenkins" -> ["Jenkins", "Jenkins CI/CD", "Jenkins Server"]
        - "wordpress" -> ["WordPress", "WordPress CMS", "WordPress Core"]
        - "mysql" -> ["MySQL", "MySQL Server", "MySQL Database"]
        
        Prioritize products that:
        - Have known CVEs and security issues
        - Are widely deployed in enterprise environments
        - Are popular development tools and frameworks
        - Are common server and infrastructure software
        - Have active security research and vulnerability disclosure
        """
        
        try:
            response = await self.llm.generate(prompt, max_tokens=300)
            json_match = re.search(r'\[.*?\]', response, re.DOTALL)
            if json_match:
                results = json.loads(json_match.group())
                return results[:6] if isinstance(results, list) else []
        except Exception as e:
            print(f"LLM completion error: {e}")
        
        return [user_input]
    
    async def gather_info(self, product_name: str) -> Dict[str, Any]:
        prompt = f"Analyze the product '{product_name}' and return JSON with: name, type, components, technologies. Be concise."
        response = await self.llm.generate(prompt)
        try:
            return json.loads(response)
        except:
            return {"name": product_name, "type": "unknown", "components": [], "technologies": []}