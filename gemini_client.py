import os
import google.generativeai as genai
import streamlit as st

class GeminiClient:
    """Gemini API client wrapper using google.generativeai package"""
    
    def __init__(self, api_key: str = None):
        # Try Streamlit secrets first, then environment variable
        if api_key:
            self.api_key = api_key
        else:
            try:
                self.api_key = st.secrets["GEMINI_API_KEY"]
            except:
                self.api_key = os.getenv('GEMINI_API_KEY')
        
        # Configure the API key
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
    
    async def generate(self, prompt: str, max_tokens: int = 150) -> str:
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"Gemini API error: {e}")
            return "Error generating response"

# Test function
def test_gemini():
    client = GeminiClient()  # Will use env variable
    response = client.generate("Explain how AI works in a few words")
    print(f"Gemini response: {response}")

if __name__ == "__main__":
    test_gemini()