import os
import google.generativeai as genai
import streamlit as st
import logging

# Debug: Print version info
print(f"google-generativeai version: {genai.__version__ if hasattr(genai, '__version__') else 'unknown'}")
print(f"Available genai attributes: {[attr for attr in dir(genai) if not attr.startswith('_')]}")

# Configure logging
logging.basicConfig(
    filename="llm_calls.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

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
        
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found in secrets or environment variables")
        
        # Configure the API key and initialize model
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
    
    async def generate(self, prompt: str, max_tokens: int = 150) -> str:
        try:
            logging.info(f"LLM Call - Prompt: {prompt}")
            response = self.model.generate_content(prompt)
            logging.info(f"LLM Response: {response.text}")
            return response.text
        except Exception as e:
            logging.error(f"LLM Call Failed - Error: {e}")
            return "Error generating response"

# Test function
def test_gemini():
    client = GeminiClient()  # Will use env variable
    response = client.generate("Explain how AI works in a few words")
    print(f"Gemini response: {response}")

if __name__ == "__main__":
    test_gemini()