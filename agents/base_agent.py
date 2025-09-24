"""
Base agent interface for standardized agent behavior
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import time

@dataclass
class AgentResult:
    """Standardized result format for all agents"""
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    execution_time: Optional[float] = None
    agent_name: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'execution_time': self.execution_time,
            'agent_name': self.agent_name
        }

class BaseAgent(ABC):
    """Base class for all threat modeling agents"""
    
    def __init__(self, llm_client, agent_name: str = None):
        self.llm = llm_client
        self.agent_name = agent_name or self.__class__.__name__
        
    @abstractmethod
    async def process(self, input_data: Dict[str, Any]) -> AgentResult:
        """Main processing method - must be implemented by each agent"""
        pass
    
    def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data - override in subclasses for specific validation"""
        return data is not None
    
    def handle_error(self, error: Exception, context: str = "") -> AgentResult:
        """Standardized error handling"""
        error_msg = f"{self.agent_name} error"
        if context:
            error_msg += f" in {context}"
        error_msg += f": {str(error)}"
        
        return AgentResult(
            success=False,
            data={},
            error=error_msg,
            agent_name=self.agent_name
        )
    
    async def execute_with_monitoring(self, input_data: Dict[str, Any]) -> AgentResult:
        """Execute agent with performance monitoring and error handling"""
        start_time = time.time()
        
        try:
            # Validate input
            if not self.validate_input(input_data):
                return AgentResult(
                    success=False,
                    data={},
                    error=f"{self.agent_name}: Invalid input data",
                    execution_time=0,
                    agent_name=self.agent_name
                )
            
            # Process
            result = await self.process(input_data)
            
            # Add execution time and agent name
            execution_time = time.time() - start_time
            result.execution_time = execution_time
            result.agent_name = self.agent_name
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_result = self.handle_error(e, "execution")
            error_result.execution_time = execution_time
            return error_result