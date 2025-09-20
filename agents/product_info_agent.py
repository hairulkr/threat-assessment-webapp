import json
import aiohttp
import urllib.parse
from typing import Dict, Any, List
import re

class ProductInfoAgent:
    """LLM-powered product information gathering with smart completion"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    async def search_cpe_products(self, query: str) -> List[str]:
        """Search CPE database for exact product names"""
        encoded_query = urllib.parse.quote_plus(query)
        url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={encoded_query}&resultsPerPage=10"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    data = await response.json()
                    products = []
                    
                    for product in data.get("products", []):
                        cpe_name = product.get("cpe", {}).get("cpeName", "")
                        if cpe_name:
                            parts = cpe_name.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product_name = parts[4]
                                full_name = f"{vendor} {product_name}".replace("_", " ")
                                if full_name not in products:
                                    products.append(full_name)
                    
                    return products[:5]
        except Exception as e:
            print(f"CPE search error: {e}")
            return []
    
    async def smart_product_completion(self, user_input: str) -> List[str]:
        """Smart product completion using CPE + LLM"""
        cpe_results = await self.search_cpe_products(user_input)
        
        if cpe_results:
            print(f"Found {len(cpe_results)} products in CPE database")
            return cpe_results
        
        prompt = f"""
        User input: "{user_input}"
        
        Complete this with exact software product names that exist in CVE databases.
        Return JSON array (1 result if exact, multiple if incomplete):
        ["product1", "product2", ...]
        """
        
        try:
            response = await self.llm.generate(prompt, max_tokens=200)
            json_match = re.search(r'\[.*?\]', response, re.DOTALL)
            if json_match:
                results = json.loads(json_match.group())
                return results[:5]
        except Exception as e:
            print(f"LLM completion error: {e}")
        
        return [user_input]
    
    async def test_cve_availability(self, product_name: str) -> Dict[str, Any]:
        """Test if product has CVEs available"""
        encoded_product = urllib.parse.quote_plus(product_name)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_product}&resultsPerPage=1"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    data = await response.json()
                    total_results = data.get("totalResults", 0)
                    
                    return {
                        "product": product_name,
                        "has_cves": total_results > 0,
                        "total_cves": total_results,
                        "sample_cve": data.get("vulnerabilities", [{}])[0].get("cve", {}).get("id", "N/A") if total_results > 0 else None
                    }
        except Exception as e:
            return {
                "product": product_name,
                "has_cves": False,
                "total_cves": 0,
                "error": str(e)
            }
    
    async def interactive_product_selection(self, user_input: str) -> str:
        """Interactive product completion with CVE validation"""
        print(f"\n🤖 AI is completing your input: '{user_input}'")
        
        completions = await self.smart_product_completion(user_input)
        print(f"💡 Found {len(completions)} matching products...")
        
        if not completions:
            print("❌ AI couldn't complete the product name.")
            return user_input
        
        print("\n🔍 Testing completed names against CVE database:")
        
        valid_products = []
        for i, product in enumerate(completions):
            print(f"  {i+1}. Testing '{product}'...", end=" ")
            cve_info = await self.test_cve_availability(product)
            
            if cve_info["has_cves"]:
                print(f"✓ ({cve_info['total_cves']} CVEs found)")
                valid_products.append((product, cve_info))
            else:
                print("✗ (No CVEs found)")
        
        if not valid_products:
            print(f"\n❌ No CVEs found for any products.")
            print(f"🔍 You can search for products at:")
            print(f"   • NVD CPE Search: https://nvd.nist.gov/products/cpe/search")
            print(f"   • CVE Search: https://cve.mitre.org/cve/search_cve_list.html")
            print(f"   • NIST NVD: https://nvd.nist.gov/vuln/search")
            
            choice = input(f"\nContinue with original input '{user_input}'? (y/n): ").strip().lower()
            return user_input if choice == 'y' else None
        
        print(f"\n✅ Products with CVE data available:")
        for i, (product, info) in enumerate(valid_products):
            print(f"  {i+1}. {product} ({info['total_cves']} CVEs)")
        
        print(f"  {len(valid_products)+1}. Use original input: '{user_input}'")
        print(f"  0. Cancel and research manually")
        
        while True:
            try:
                choice = input(f"\nSelect option (0-{len(valid_products)+1}): ").strip()
                choice_num = int(choice)
                
                if choice_num == 0:
                    return None
                elif choice_num == len(valid_products) + 1:
                    return user_input
                elif 1 <= choice_num <= len(valid_products):
                    selected_product = valid_products[choice_num - 1][0]
                    print(f"Selected: {selected_product}")
                    return selected_product
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a valid number.")
    
    async def gather_info(self, product_name: str) -> Dict[str, Any]:
        prompt = f"Analyze the product '{product_name}' and return JSON with: name, type, components, technologies. Be concise."
        response = await self.llm.generate(prompt)
        try:
            return json.loads(response)
        except:
            return {"name": product_name, "type": "unknown", "components": [], "technologies": []}