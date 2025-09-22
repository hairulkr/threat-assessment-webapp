import requests
import json

def test_perplexity_api(api_key):
    """Test Perplexity API with correct model names"""
    
    url = "https://api.perplexity.ai/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Test current Perplexity model names (2024)
    models_to_test = [
        "llama-3.1-sonar-small-128k-online",
        "llama-3.1-sonar-large-128k-online",
        "llama-3.1-sonar-huge-128k-online",
        "llama-3.1-8b-instruct",
        "llama-3.1-70b-instruct",
        "sonar-pro",
        "sonar"
    ]
    
    for model in models_to_test:
        print(f"\n--- Testing model: {model} ---")
        data = {
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": "What is cybersecurity?"
                }
            ]
        }
        
        try:
            response = requests.post(url, json=data, headers=headers, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ SUCCESS with {model}!")
                print(f"Response: {result['choices'][0]['message']['content'][:100]}...")
                return model  # Return working model
            else:
                error_msg = response.json().get('error', {}).get('message', response.text)
                print(f"❌ Failed: {error_msg}")
                
        except Exception as e:
            print(f"❌ Exception: {e}")
    
    return None  # No working model found

if __name__ == "__main__":
    # Test with your API key
    api_key = input("Enter your Perplexity API key: ").strip()
    working_model = test_perplexity_api(api_key)
    
    if working_model:
        print(f"\n🎉 Working model found: {working_model}")
    else:
        print("\n❌ No working models found")