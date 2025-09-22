import requests
import os

# Simple test of Perplexity API
api_key = os.getenv('PERPLEXITY_API_KEY')

if not api_key:
    print("❌ No PERPLEXITY_API_KEY found")
    exit()

print(f"✅ API Key found: {api_key[:10]}...")

# Test 1: Simple model
data1 = {
    "model": "llama-3.1-sonar-small-128k-online",
    "messages": [{"role": "user", "content": "Hello"}]
}

# Test 2: Original model
data2 = {
    "model": "sonar-pro", 
    "messages": [{"role": "user", "content": "Hello"}]
}

headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

print("\n🧪 Testing new model...")
try:
    response = requests.post("https://api.perplexity.ai/chat/completions", 
                           json=data1, headers=headers, timeout=30)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print("✅ New model works!")
        result = response.json()
        print(f"Response: {result['choices'][0]['message']['content'][:100]}...")
    else:
        print(f"❌ Error: {response.text}")
except Exception as e:
    print(f"❌ Exception: {e}")

print("\n🧪 Testing original model...")
try:
    response = requests.post("https://api.perplexity.ai/chat/completions", 
                           json=data2, headers=headers, timeout=30)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print("✅ Original model works!")
        result = response.json()
        print(f"Response: {result['choices'][0]['message']['content'][:100]}...")
    else:
        print(f"❌ Error: {response.text}")
except Exception as e:
    print(f"❌ Exception: {e}")