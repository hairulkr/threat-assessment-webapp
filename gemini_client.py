# DEPRECATED: This file is kept for backward compatibility only.
# Use llm_client.py instead for all new code.
# The LLMClient class provides unified access to both Gemini and Perplexity.

from llm_client import LLMClient

# Backward compatibility wrapper
class GeminiClient(LLMClient):
    """Deprecated: Use LLMClient('gemini') instead"""
    
    def __init__(self, api_key: str = None, model: str = None):
        print("Warning: GeminiClient is deprecated. Use LLMClient('gemini') instead.")
        super().__init__("gemini", api_key, model)