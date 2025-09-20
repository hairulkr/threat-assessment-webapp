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
    
    async def get_product_suggestions(self, user_input: str) -> List[str]:
        """Get product suggestions using LLM - more flexible than CPE database"""
        return await self.smart_product_completion(user_input)
    
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
        """Smart product completion using LLM"""
        if len(user_input) < 2:
            return []
        
        prompt = f"""
        User input: "{user_input}"
        
        Complete this with the LATEST and MOST CURRENT software products available on the internet as of 2024. Focus on newest releases, latest versions, and cutting-edge technologies.
        Return JSON array (1 result if exact, multiple if incomplete):
        ["product1", "product2", ...]
        
        Examples with LATEST versions:
        - "visual" -> ["Visual Studio Code 2024", "Visual Studio 2022 17.8", "Visual Studio Community 2022"]
        - "apache" -> ["Apache Tomcat 10.1", "Apache HTTP Server 2.4.58", "Apache Kafka 3.6"]
        - "docker" -> ["Docker Desktop 4.25", "Docker Engine 24.0", "Docker Compose v2"]
        - "node" -> ["Node.js 21.x", "Node.js 20 LTS", "Node.js Latest"]
        - "python" -> ["Python 3.12", "Python 3.11", "Python Latest"]
        - "react" -> ["React 18.2", "React Native 0.73", "Next.js 14"]
        - "spring" -> ["Spring Boot 3.2", "Spring Framework 6.1", "Spring Security 6.2"]
        - "kubernetes" -> ["Kubernetes 1.29", "K8s Latest", "OpenShift 4.14"]
        - "terraform" -> ["Terraform 1.6", "Terraform Latest", "HashiCorp Terraform"]
        - "mongodb" -> ["MongoDB 7.0", "MongoDB Atlas", "MongoDB Community"]
        
        Focus on:
        - Latest stable releases and versions from 2024
        - Newest cloud-native and modern technologies
        - Current enterprise software and tools
        - Latest development frameworks and platforms
        - Most recent security tools and infrastructure
        - Cutting-edge AI/ML platforms and tools
        - Modern containerization and orchestration tools
        """
        
        try:
            response = await self.llm.generate(prompt, max_tokens=200)
            json_match = re.search(r'\[.*?\]', response, re.DOTALL)
            if json_match:
                results = json.loads(json_match.group())
                return results[:5] if isinstance(results, list) else []
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