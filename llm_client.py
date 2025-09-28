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
        elif self.provider == "ollama":
            self._init_ollama()
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
    
    def _init_ollama(self):
        """Initialize Ollama client"""
        # Try to get API key for cloud usage (optional)
        if not self.api_key:
            try:
                self.api_key = st.secrets["OLLAMA_API_KEY"]
            except (KeyError, AttributeError):
                self.api_key = os.getenv('OLLAMA_API_KEY')
        
        # Default to cloud model if no model specified
        if not self.selected_model:
            self.selected_model = "deepseek-v3.1:671b-cloud"  # Cloud available model
        
        self.model = "ollama-client"
        self.model_name = self.selected_model
    
    def is_available(self) -> bool:
        """Check if the LLM client is available"""
        if self.provider == "ollama":
            return self.model is not None  # Ollama can work locally without API key
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
            elif self.provider == "ollama":
                result = await self._call_ollama(prompt, max_tokens)
                
                # Return error result for Ollama failures
                if ("error" in result.lower() or "timeout" in result.lower() or 
                    "exception" in result.lower() or "502" in result.lower() or 
                    "upstream" in result.lower() or len(result) < 50):
                    
                    logging.warning(f"Ollama failed: {result[:100]}...")
                    # Just return the error - no fallback available
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
    
    async def _call_ollama(self, prompt: str, max_tokens: int) -> str:
        """Call Ollama with automatic Gemini fallback on 502 errors"""
        import asyncio
        from datetime import datetime
        
        start_time = datetime.now()
        logging.info(f"Ollama API call started at {start_time}")
        
        def make_request():
            import time
            max_retries = 3
            
            for attempt in range(max_retries):
                try:
                    import ollama
                    
                    # Try local first, then cloud if API key available
                    client = None
                    
                    # Try local Ollama first
                    try:
                        client = ollama.Client()
                        # Test connection
                        client.list()
                        logging.info("Using local Ollama")
                    except Exception:
                        client = None
                    
                    # If local fails and we have API key, try cloud
                    if client is None and self.api_key:
                        try:
                            client = ollama.Client(
                                host='https://ollama.com',
                                headers={'Authorization': self.api_key}
                            )
                            logging.info("Using Ollama Cloud")
                        except Exception:
                            client = None
                    
                    if client is None:
                        raise Exception("Ollama not available locally or in cloud")
                    
                    logging.info(f"Making Ollama request (attempt {attempt + 1}/{max_retries}) with {len(prompt)} chars")
                    
                    response = client.chat(
                        model=self.selected_model,
                        messages=[
                            {
                                'role': 'user',
                                'content': prompt,
                            },
                        ],
                        options={
                            'temperature': 0.1,
                            'top_p': 0.9
                        }
                    )
                    
                    elapsed = (datetime.now() - start_time).total_seconds()
                    logging.info(f"Ollama response received after {elapsed:.1f}s")
                    
                    content = response['message']['content']
                    logging.info(f"Ollama success: {len(content)} chars returned")
                    return content
                        
                except ImportError:
                    raise Exception("Ollama client not installed")
                except Exception as e:
                    error_str = str(e).lower()
                    is_server_error = "502" in error_str or "upstream" in error_str or "bad gateway" in error_str
                    
                    if is_server_error and attempt < max_retries - 1:
                        wait_time = (attempt + 1) * 2  # 2, 4, 6 seconds
                        logging.warning(f"Ollama 502 error on attempt {attempt + 1}, retrying in {wait_time}s...")
                        time.sleep(wait_time)
                        continue
                    elif is_server_error:
                        raise Exception(f"Ollama server error (502) after {max_retries} attempts: {str(e)}")
                    else:
                        raise Exception(f"Ollama error: {str(e)}")
            
            raise Exception("Max retries exceeded")
        
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, make_request)
            return result
        except Exception as e:
            error_msg = str(e)
            logging.error(f"Ollama failed: {error_msg}")
            
            # Provide helpful error message for 502 errors
            if "502" in error_msg or "upstream" in error_msg or "server error" in error_msg:
                return f"Ollama server is currently unavailable (502 Bad Gateway). Tried 3 times with delays. Please try again in a few minutes or check if Ollama is running locally. Error: {error_msg}"
            
            return error_msg

def get_available_providers() -> Dict[str, Dict[str, str]]:
    """Get status of all available LLM providers"""
    providers = {}
    
    # Check Ollama models (cloud available)
    ollama_models = {
        "gpt-oss:20b-cloud": {"name": "GPT-OSS 20B", "desc": "Fast open source model"},
        "gpt-oss:120b-cloud": {"name": "GPT-OSS 120B", "desc": "Large open source model"},
        "deepseek-v3.1:671b-cloud": {"name": "DeepSeek V3.1 671B", "desc": "Advanced reasoning model"},
        "qwen3-coder:480b-cloud": {"name": "Qwen3 Coder 480B", "desc": "Code-specialized model"}
    }
    
    for model_id, model_info in ollama_models.items():
        ollama_client = LLMClient("ollama", model=model_id)
        status = ollama_client.get_status()
        # Create clean key: gpt-oss:120b -> ollama-gpt-oss-120b
        clean_key = f"ollama-{model_id.replace(':', '-').replace('.', '-').replace('_', '-')}"
        providers[clean_key] = {
            "status": status["status"],
            "model": model_info["name"],
            "description": model_info["desc"],
            "provider": "Ollama",
            "model_id": model_id
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