"""
Centralized configuration for all agents
"""
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class AgentConfig:
    """Configuration settings for threat modeling agents"""
    
    # Timeout settings (seconds)
    timeouts: Dict[str, int] = None
    
    # Retry settings
    retry_counts: Dict[str, int] = None
    
    # Fallback settings
    fallback_enabled: Dict[str, bool] = None
    
    # LLM settings
    max_tokens: Dict[str, int] = None
    
    # Performance settings
    parallel_processing: bool = True
    
    def __post_init__(self):
        if self.timeouts is None:
            self.timeouts = {
                'product': 30,
                'intelligence': 90,
                'controls': 150,
                'report': 180,
                'default': 60
            }
        
        if self.retry_counts is None:
            self.retry_counts = {
                'product': 2,
                'intelligence': 1,  # Intelligence has its own internal retries
                'controls': 2,
                'report': 1,
                'default': 1
            }
        
        if self.fallback_enabled is None:
            self.fallback_enabled = {
                'product': True,
                'intelligence': False,  # Critical - no fallback
                'controls': True,
                'report': True,
                'default': True
            }
        
        if self.max_tokens is None:
            self.max_tokens = {
                'product': 1000,
                'intelligence': 2000,
                'controls': 1500,
                'report': 3000,
                'default': 1000
            }
    
    def get_timeout(self, agent_name: str) -> int:
        """Get timeout for specific agent"""
        return self.timeouts.get(agent_name.lower(), self.timeouts['default'])
    
    def get_retry_count(self, agent_name: str) -> int:
        """Get retry count for specific agent"""
        return self.retry_counts.get(agent_name.lower(), self.retry_counts['default'])
    
    def get_fallback_enabled(self, agent_name: str) -> bool:
        """Check if fallback is enabled for specific agent"""
        return self.fallback_enabled.get(agent_name.lower(), self.fallback_enabled['default'])
    
    def get_max_tokens(self, agent_name: str) -> int:
        """Get max tokens for specific agent"""
        return self.max_tokens.get(agent_name.lower(), self.max_tokens['default'])

# Global configuration instance
AGENT_CONFIG = AgentConfig()