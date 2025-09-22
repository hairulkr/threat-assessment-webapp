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
    
    def __init__(self, provider: str = "gemini", api_key: str = None, model: str = None):
        self.provider = provider.lower()
        self.api_key = api_key
        self.model_name = None
        self.selected_model = model
        
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
            except (KeyError, AttributeError):
                self.api_key = os.getenv('GEMINI_API_KEY')
        
        if not self.api_key:
            self.model = None
            self.model_name = "No API Key"
            return
        
        # Default to 2.5-flash if no model specified
        if not self.selected_model:
            self.selected_model = "gemini-2.5-flash"
        
        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(self.selected_model)
            self.model_name = self.selected_model
        except Exception as e:
            self.model = None
            self.model_name = f"Error: {str(e)}"
    
    def _init_perplexity(self):
        """Initialize Perplexity client"""
        if not self.api_key:
            try:
                self.api_key = st.secrets["PERPLEXITY_API_KEY"]
            except (KeyError, AttributeError):
                self.api_key = os.getenv('PERPLEXITY_API_KEY')
        
        if not self.api_key:
            self.model = None
            self.model_name = "No API Key"
            return
        
        self.model = "perplexity-client"
        self.model_name = "sonar-pro"
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
                
                # Check if Perplexity failed and fallback to Gemini if available
                if ("error" in result.lower() or "timeout" in result.lower() or 
                    "exception" in result.lower() or len(result) < 50):
                    
                    logging.warning(f"Perplexity failed: {result[:100]}... Attempting Gemini fallback")
                    
                    # Try Gemini as fallback
                    try:
                        gemini_key = None
                        try:
                            gemini_key = st.secrets["GEMINI_API_KEY"]
                        except (KeyError, AttributeError):
                            gemini_key = os.getenv('GEMINI_API_KEY')
                        
                        if gemini_key:
                            genai.configure(api_key=gemini_key)
                            fallback_model = self.selected_model or "gemini-2.5-flash"
                            gemini_model = genai.GenerativeModel(fallback_model)
                            fallback_response = gemini_model.generate_content(prompt)
                            result = f"[Fallback to Gemini] {fallback_response.text}"
                            logging.info("Successfully used Gemini fallback")
                        else:
                            result = f"Perplexity failed and no Gemini key available: {result}"
                    except Exception as fallback_error:
                        logging.error(f"Gemini fallback also failed: {str(fallback_error)}")
                        result = f"Both Perplexity and Gemini failed: {result}"
            else:
                result = "Error: Unsupported provider"
            
            logging.info(f"LLM Response ({self.provider}): {result[:100]}...")
            return result
            
        except Exception as e:
            error_msg = f"Error generating response with {self.provider}: {str(e)}"
            logging.error(error_msg)
            return error_msg
    
    async def _call_perplexity(self, prompt: str, max_tokens: int) -> str:
        """Call Perplexity API with better error handling"""
        import requests
        import asyncio
        from datetime import datetime
        
        # Log the start of the call
        start_time = datetime.now()
        logging.info(f"Perplexity API call started at {start_time}")
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Don't truncate - sonar-pro can handle large contexts
        # Truncation was likely breaking the JSON structure in prompts
        
        data = {
            "model": "sonar-pro",
            "messages": [
                {
                    "role": "user", 
                    "content": prompt
                }
            ],
            "max_tokens": max_tokens,  # Don't artificially limit
            "temperature": 0.1,  # Lower for more consistent responses
            "top_p": 0.9,
            "top_k": 0,
            "stream": False,
            "presence_penalty": 0,
            "frequency_penalty": 1
        }
        
        def make_request():
            """Synchronous request function"""
            try:
                logging.info(f"Making Perplexity request with {len(prompt)} chars")
                # Perplexity can be slow for complex queries - use longer timeout
                response = requests.post(
                    self.base_url, 
                    json=data, 
                    headers=headers, 
                    timeout=120  # Increased timeout for complex queries
                )
                
                elapsed = (datetime.now() - start_time).total_seconds()
                logging.info(f"Perplexity response received after {elapsed:.1f}s, status: {response.status_code}")
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Validate response structure
                    if not isinstance(result, dict):
                        raise ValueError("Invalid API response format: not a dictionary")
                    
                    if "choices" not in result or not isinstance(result["choices"], list) or len(result["choices"]) == 0:
                        raise ValueError("Invalid API response: missing or empty choices")
                    
                    choice = result["choices"][0]
                    if not isinstance(choice, dict) or "message" not in choice:
                        raise ValueError("Invalid API response: missing message in choice")
                    
                    message = choice["message"]
                    if not isinstance(message, dict) or "content" not in message:
                        raise ValueError("Invalid API response: missing content in message")
                    
                    content = message["content"]
                    if not isinstance(content, str):
                        raise ValueError("Invalid API response: content is not a string")
                    
                    # Add citations if available
                    if "citations" in result and isinstance(result["citations"], list):
                        citations = "\n\nSources:\n" + "\n".join([f"- {cite}" for cite in result["citations"][:3] if isinstance(cite, str)])
                        content += citations
                    
                    logging.info(f"Perplexity success: {len(content)} chars returned")
                    return content
                else:
                    error_text = response.text[:500]  # Limit error text
                    logging.error(f"Perplexity API error {response.status_code}: {error_text}")
                    return f"Perplexity API error {response.status_code}: {error_text}"
                    
            except requests.exceptions.Timeout:
                elapsed = (datetime.now() - start_time).total_seconds()
                logging.error(f"Perplexity timeout after {elapsed:.1f}s")
                return "Perplexity API timeout - switching to fallback response"
            except Exception as e:
                elapsed = (datetime.now() - start_time).total_seconds()
                logging.error(f"Perplexity exception after {elapsed:.1f}s: {str(e)}")
                return f"Perplexity error: {str(e)}"
        
        # Run the synchronous request in a thread pool
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, make_request)
            return result
        except Exception as e:
            logging.error(f"Async execution error: {str(e)}")
            return f"Execution error: {str(e)}"

def get_available_providers() -> Dict[str, Dict[str, str]]:
    """Get status of all available LLM providers"""
    providers = {}
    
    # Check Gemini models
    gemini_models = {
        "gemini-2.0-flash": "Gemini 2.0 Flash",
        "gemini-2.5-flash": "Gemini 2.5 Flash", 
        "gemini-2.5-pro": "Gemini 2.5 Pro"
    }
    
    for model_id, model_name in gemini_models.items():
        gemini_client = LLMClient("gemini", model=model_id)
        status = gemini_client.get_status()
        providers[f"gemini-{model_id.split('-')[-1]}"] = {
            "status": status["status"],
            "model": model_name,
            "provider": "Gemini",
            "model_id": model_id
        }
    
    # Check Perplexity
    perplexity_client = LLMClient("perplexity")
    status = perplexity_client.get_status()
    providers["perplexity"] = {
        "status": status["status"],
        "model": "Sonar Pro",
        "provider": "Perplexity",
        "model_id": "sonar-pro"
    }
    
    return providers

# Backward compatibility - keep GeminiClient for existing code
class GeminiClient(LLMClient):
    """Backward compatible Gemini client"""
    
    def __init__(self, api_key: str = None, model: str = None):
        super().__init__("gemini", api_key, model)

if __name__ == "__main__":
    # Test both providers
    providers = get_available_providers()
    for name, status in providers.items():
        print(f"{name}: {status}")