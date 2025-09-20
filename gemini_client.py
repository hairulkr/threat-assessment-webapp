import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

class GeminiClient:
    """Gemini API client wrapper using google.genai package"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        # Explicitly set the API key to avoid confusion with GOOGLE_API_KEY
        self.client = genai.Client(api_key=self.api_key)
    
    async def generate(self, prompt: str, max_tokens: int = 150) -> str:
        try:
            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
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