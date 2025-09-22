import streamlit as st
import requests
import json
import os

def test_perplexity_in_streamlit():
    """Test Perplexity API directly in Streamlit environment"""
    
    st.title("Perplexity API Debug in Streamlit")
    
    # Get API key from secrets or input
    api_key = None
    try:
        api_key = st.secrets["PERPLEXITY_API_KEY"]
        st.success("✅ API key loaded from Streamlit secrets")
    except:
        api_key = os.getenv('PERPLEXITY_API_KEY')
        if api_key:
            st.success("✅ API key loaded from environment")
        else:
            api_key = st.text_input("Enter Perplexity API key:", type="password")
    
    if api_key and st.button("Test Perplexity API"):
        with st.spinner("Testing Perplexity API..."):
            
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
                        "content": "What is cybersecurity?"
                    }
                ]
            }
            
            st.write("**Request Details:**")
            st.code(f"URL: {url}")
            st.code(f"Headers: {headers}")
            st.code(f"Data: {json.dumps(data, indent=2)}")
            
            try:
                # Test with requests (same as working script)
                response = requests.post(url, json=data, headers=headers, timeout=30)
                
                st.write(f"**Status Code:** {response.status_code}")
                
                if response.status_code == 200:
                    result = response.json()
                    st.success("✅ SUCCESS!")
                    st.write("**Response:**")
                    st.json(result)
                    
                    content = result["choices"][0]["message"]["content"]
                    st.write("**Content:**")
                    st.write(content)
                    
                else:
                    st.error("❌ FAILED!")
                    st.write("**Error Response:**")
                    st.code(response.text)
                    
            except Exception as e:
                st.error(f"❌ Exception: {e}")
                st.write("**Full Error:**")
                st.exception(e)

if __name__ == "__main__":
    test_perplexity_in_streamlit()