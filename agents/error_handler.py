"""
Enhanced error handling for agents
"""
import asyncio
from typing import Dict, Any, Callable, Optional
from .base_agent import AgentResult
from .agent_config import AGENT_CONFIG
from .agent_monitor import AGENT_MONITOR

class AgentErrorHandler:
    """Enhanced error handling with retries and fallbacks"""
    
    @staticmethod
    async def execute_with_retry(
        agent_name: str,
        operation: Callable,
        input_data: Dict[str, Any],
        fallback_operation: Optional[Callable] = None
    ) -> AgentResult:
        """Execute operation with retry logic and fallback"""
        
        retry_count = AGENT_CONFIG.get_retry_count(agent_name)
        timeout = AGENT_CONFIG.get_timeout(agent_name)
        fallback_enabled = AGENT_CONFIG.get_fallback_enabled(agent_name)
        
        start_time = AGENT_MONITOR.start_execution(agent_name)
        last_error = None
        
        # Try main operation with retries
        for attempt in range(retry_count + 1):
            try:
                result = await asyncio.wait_for(
                    operation(input_data),
                    timeout=timeout
                )
                
                # Success - wrap result if it's not already an AgentResult
                AGENT_MONITOR.end_execution(agent_name, start_time, True)
                if isinstance(result, AgentResult):
                    return result
                else:
                    return AgentResult(
                        success=True,
                        data=result,
                        agent_name=agent_name
                    )
                
            except asyncio.TimeoutError as e:
                last_error = f"Timeout after {timeout}s (attempt {attempt + 1})"
                if attempt < retry_count:
                    await asyncio.sleep(1)  # Brief delay before retry
                    continue
                break
                
            except Exception as e:
                last_error = f"{str(e)} (attempt {attempt + 1})"
                if attempt < retry_count:
                    await asyncio.sleep(1)  # Brief delay before retry
                    continue
                break
        
        # Main operation failed, try fallback if enabled
        if fallback_enabled and fallback_operation:
            try:
                result = await asyncio.wait_for(
                    fallback_operation(input_data),
                    timeout=timeout // 2  # Shorter timeout for fallback
                )
                
                # Fallback success - wrap result if needed
                AGENT_MONITOR.end_execution(agent_name, start_time, True, f"Fallback used: {last_error}")
                if isinstance(result, AgentResult):
                    result.error = f"Main operation failed, used fallback: {last_error}"
                    return result
                else:
                    return AgentResult(
                        success=True,
                        data=result,
                        error=f"Main operation failed, used fallback: {last_error}",
                        agent_name=agent_name
                    )
                
            except Exception as fallback_error:
                last_error = f"Main: {last_error}, Fallback: {str(fallback_error)}"
        
        # Both main and fallback failed
        AGENT_MONITOR.end_execution(agent_name, start_time, False, last_error)
        return AgentResult(
            success=False,
            data={},
            error=last_error,
            agent_name=agent_name
        )
    
    @staticmethod
    def create_fallback_data(agent_name: str, error_context: str) -> Dict[str, Any]:
        """Create fallback data based on agent type"""
        fallback_data = {
            'product': {
                'name': 'Unknown Product',
                'description': 'Product analysis failed',
                'technologies': [],
                'components': []
            },
            'intelligence': {
                'threats': [],
                'threat_context': {'context_summary': 'Intelligence gathering failed'},
                'risk_assessment': {'overall_risk_level': 'MEDIUM', 'risk_score': 5.0},
                'mitre_mapping': [],
                'validation_summary': {'relevance_score': 0.0, 'data_quality': 'low'}
            },
            'controls': {
                'preventive': ['Multi-factor authentication', 'Regular patching'],
                'detective': ['Security monitoring', 'Log analysis'],
                'corrective': ['Incident response plan', 'Backup and recovery']
            },
            'report': '<h1>Threat Assessment Report</h1><p>Report generation failed. Please try again.</p>'
        }
        
        agent_key = agent_name.lower().replace('agent', '')
        return fallback_data.get(agent_key, {})