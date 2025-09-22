import requests
import json

def test_sonar_pro(api_key):
    """Test sonar-pro model and show full output"""
    
    url = "https://api.perplexity.ai/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": "sonar-pro",
        "messages": [
            {
                "role": "user",
                "content": "What are the latest cybersecurity threats in 2024?"
            }
        ]
    }
    
    print("Testing sonar-pro model...")
    print(f"URL: {url}")
    print(f"Headers: {headers}")
    print(f"Data: {json.dumps(data, indent=2)}")
    
    try:
        response = requests.post(url, json=data, headers=headers, timeout=30)
        
        print(f"\nStatus Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("\n✅ SUCCESS!")
            print(f"\nFull Response:")
            print(json.dumps(result, indent=2))
            
            content = result['choices'][0]['message']['content']
            print(f"\n📝 Content Only:")
            print(content)
            
            return True
        else:
            print("\n❌ FAILED!")
            print(f"Error Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"\n❌ Exception: {e}")
        return False

if __name__ == "__main__":
    api_key = input("Enter your Perplexity API key: ").strip()
    test_sonar_pro(api_key)