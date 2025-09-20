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
        """Get product suggestions with CVE validation"""
        if len(user_input) < 2:
            return []
        
        # Get CPE suggestions
        cpe_results = await self.search_cpe_products(user_input)
        
        # Test each suggestion for CVE availability
        validated_suggestions = []
        for product_info in cpe_results:
            cve_info = await self.test_cve_availability(product_info["name"])
            if cve_info["has_cves"]:
                validated_suggestions.append({
                    "name": product_info["name"],
                    "cve_count": cve_info["total_cves"],
                    "vendor": product_info.get("vendor", ""),
                    "source": "CPE Database"
                })
        
        return validated_suggestions[:5]
    
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
        """Legacy method for backward compatibility"""
        suggestions = await self.get_product_suggestions(user_input)
        return [s["name"] for s in suggestions if isinstance(s, dict)]
    
    async def gather_info(self, product_name: str) -> Dict[str, Any]:
        prompt = f"Analyze the product '{product_name}' and return JSON with: name, type, components, technologies. Be concise."
        response = await self.llm.generate(prompt)
        try:
            return json.loads(response)
        except:
            return {"name": product_name, "type": "unknown", "components": [], "technologies": []}