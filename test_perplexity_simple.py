import asyncio
from llm_client import LLMClient

async def test_perplexity_simple():
    """Simple test of Perplexity API call"""
    
    print("Testing Perplexity with simple prompt...")
    
    # Create Perplexity client
    llm = LLMClient("perplexity")
    
    # Check if available
    print(f"Available: {llm.is_available()}")
    print(f"Status: {llm.get_status()}")
    
    if llm.is_available():
        # Simple test prompt
        result = await llm.generate("What is cybersecurity?", max_tokens=100)
        print(f"Result: {result}")
    else:
        print("Perplexity not available")

if __name__ == "__main__":
    asyncio.run(test_perplexity_simple())