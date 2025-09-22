import streamlit as st
import asyncio
import os
import requests
import traceback
from llm_client import LLMClient

st.set_page_config(page_title="Perplexity Debug", page_icon="🔍")

st.title("🔍 Perplexity API Debug Page")

st.markdown("""
This page tests the Perplexity API connection directly to isolate any issues.
""")

# API Key input
api_key = st.text_input("Perplexity API Key", type="password", 
                       value=os.getenv('PERPLEXITY_API_KEY', ''))

if st.button("Test Perplexity API"):
    if not api_key:
        st.error("Please enter your Perplexity API key")
    else:
        with st.spinner("Testing Perplexity API..."):
            
            # Test 1: Direct API call
            st.subheader("Test 1: Direct API Call")
            try:
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
                
                st.write("📡 Making direct API call...")
                response = requests.post(
                    "https://api.perplexity.ai/chat/completions", 
                    json=data, 
                    headers=headers, 
                    timeout=30
                )
                
                st.write(f"Status Code: {response.status_code}")
                
                if response.status_code == 200:
                    result = response.json()
                    content = result["choices"][0]["message"]["content"]
                    st.success("✅ Direct API call successful!")
                    st.write("Response:", content[:200] + "...")
                else:
                    st.error(f"❌ Direct API call failed: {response.status_code}")
                    st.write("Error response:", response.text)
                    
            except Exception as e:
                st.error(f"❌ Direct API call exception: {str(e)}")
                st.write("Full traceback:", traceback.format_exc())
            
            # Test 2: LLMClient
            st.subheader("Test 2: LLMClient")
            try:
                st.write("🔧 Creating LLMClient...")
                client = LLMClient("perplexity", api_key)
                
                st.write("📊 Client status:", client.get_status())
                
                if client.is_available():
                    st.write("🚀 Calling generate method...")
                    
                    async def test_generate():
                        return await client.generate("What are the top 3 cybersecurity threats?")
                    
                    result = asyncio.run(test_generate())
                    st.success("✅ LLMClient call successful!")
                    st.write("Response:", result)
                else:
                    st.error("❌ LLMClient not available")
                    
            except Exception as e:
                st.error(f"❌ LLMClient exception: {str(e)}")
                st.write("Full traceback:", traceback.format_exc())

# Environment info
st.subheader("Environment Information")
st.write("Python version:", st.__version__)
st.write("Streamlit version:", st.__version__)
st.write("Current working directory:", os.getcwd())

# Show environment variables (without values)
env_vars = [key for key in os.environ.keys() if 'PERPLEXITY' in key.upper()]
st.write("Perplexity environment variables found:", env_vars)