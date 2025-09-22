import os
import google.generativeai as genai
import requests
import streamlit as st
import logging
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(
    filename="llm_calls.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class LLMClient:
    """Unified LLM client supporting Gemini and Perplexity"""
    
    def __init__(self, provider: str = "gemini", api_key: str = None):
        self.provider = provider.lower()
        self.api_key = api_key
        self.model_name = None
        
        if self.provider == "gemini":
            self._init_gemini()
        elif self.provider == "perplexity":
            self._init_perplexity()
        else:
            raise ValueError(f"Unsupported provider: {provider}")
    
    def _init_gemini(self):
        """Initialize Gemini client"""
        if not self.api_key:
            try:
                self.api_key = st.secrets["GEMINI_API_KEY"]
            except:
                self.api_key = os.getenv('GEMINI_API_KEY')
        
        if not self.api_key:
            self.model = None
            self.model_name = "No API Key"
            return
        
        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
            self.model_name = "gemini-1.5-flash"
        except Exception as e:
            self.model = None
            self.model_name = f"Error: {str(e)}"
    
    def _init_perplexity(self):
        """Initialize Perplexity client"""
        if not self.api_key:
            try:
                self.api_key = st.secrets["PERPLEXITY_API_KEY"]
            except:
                self.api_key = os.getenv('PERPLEXITY_API_KEY')
        
        if not self.api_key:
            self.model = None
            self.model_name = "No API Key"
            return
        
        self.model = "perplexity-client"
        self.model_name = "llama-3.1-sonar-large-128k-online"
        self.base_url = "https://api.perplexity.ai/chat/completions"
    
    def is_available(self) -> bool:
        """Check if the LLM client is available"""
        return self.model is not None and self.api_key is not None
    
    def get_status(self) -> Dict[str, str]:
        """Get status information about the LLM client"""
        if self.is_available():
            return {
                "status": "✅ Available",
                "model": self.model_name,
                "provider": self.provider.title()
            }
        else:
            return {
                "status": "❌ No API Key",
                "model": self.model_name or "N/A",
                "provider": self.provider.title()
            }
    
    async def generate(self, prompt: str, max_tokens: int = 150) -> str:
        """Generate response using the configured provider"""
        if not self.is_available():
            return f"Error: {self.provider.title()} API key not available"
        
        try:
            logging.info(f"LLM Call ({self.provider}) - Model: {self.model_name} - Prompt: {prompt[:100]}...")
            
            if self.provider == "gemini":
                response = self.model.generate_content(prompt)
                result = response.text
            elif self.provider == "perplexity":
                result = await self._call_perplexity(prompt, max_tokens)
            else:
                result = "Error: Unsupported provider"
            
            logging.info(f"LLM Response ({self.provider}): {result[:100]}...")
            return result
            
        except Exception as e:
            error_msg = f"Error generating response with {self.provider}: {str(e)}"
            logging.error(error_msg)
            return error_msg
    
    async def _call_perplexity(self, prompt: str, max_tokens: int) -> str:
        """Call Perplexity API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model_name,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert providing threat intelligence analysis."
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
            "top_p": 0.9,
            "return_citations": True,
            "search_domain_filter": ["perplexity.ai"],
            "return_images": False,
            "return_related_questions": False,
            "search_recency_filter": "month",
            "top_k": 0,
            "stream": False,
            "presence_penalty": 0,
            "frequency_penalty": 1
        }
        
        try:
            response = requests.post(self.base_url, json=data, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            
            # Add citations if available
            if "citations" in result and result["citations"]:
                citations = "\n\nSources:\n" + "\n".join([f"- {cite}" for cite in result["citations"][:3]])
                content += citations
            
            return content
            
        except requests.exceptions.RequestException as e:
            return f"Perplexity API error: {str(e)}"
        except KeyError as e:
            return f"Perplexity response parsing error: {str(e)}"

def get_available_providers() -> Dict[str, Dict[str, str]]:
    """Get status of all available LLM providers"""
    providers = {}
    
    # Check Gemini
    gemini_client = LLMClient("gemini")
    providers["gemini"] = gemini_client.get_status()
    
    # Check Perplexity
    perplexity_client = LLMClient("perplexity")
    providers["perplexity"] = perplexity_client.get_status()
    
    return providers

# Backward compatibility - keep GeminiClient for existing code
class GeminiClient(LLMClient):
    """Backward compatible Gemini client"""
    
    def __init__(self, api_key: str = None):
        super().__init__("gemini", api_key)

if __name__ == "__main__":
    # Test both providers
    providers = get_available_providers()
    for name, status in providers.items():
        print(f"{name}: {status}")