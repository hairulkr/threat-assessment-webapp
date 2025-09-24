"""
Performance monitoring for agents
"""
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import time

@dataclass
class AgentMetrics:
    """Metrics for a single agent execution"""
    agent_name: str
    start_time: float
    end_time: float
    success: bool
    error: Optional[str] = None
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

@dataclass
class AgentStats:
    """Aggregated statistics for an agent"""
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    total_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    recent_errors: List[str] = field(default_factory=list)
    
    @property
    def success_rate(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.successful_executions / self.total_executions
    
    @property
    def average_time(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.total_time / self.total_executions

class AgentMonitor:
    """Monitor agent performance and health"""
    
    def __init__(self):
        self.metrics: List[AgentMetrics] = []
        self.stats: Dict[str, AgentStats] = {}
        self.max_recent_errors = 5
    
    def start_execution(self, agent_name: str) -> float:
        """Start tracking an agent execution"""
        return time.time()
    
    def end_execution(self, agent_name: str, start_time: float, success: bool, error: str = None):
        """End tracking an agent execution"""
        end_time = time.time()
        
        # Record metrics
        metric = AgentMetrics(
            agent_name=agent_name,
            start_time=start_time,
            end_time=end_time,
            success=success,
            error=error
        )
        self.metrics.append(metric)
        
        # Update stats
        if agent_name not in self.stats:
            self.stats[agent_name] = AgentStats()
        
        stats = self.stats[agent_name]
        stats.total_executions += 1
        stats.total_time += metric.duration
        
        if success:
            stats.successful_executions += 1
        else:
            stats.failed_executions += 1
            if error:
                stats.recent_errors.append(error)
                # Keep only recent errors
                if len(stats.recent_errors) > self.max_recent_errors:
                    stats.recent_errors = stats.recent_errors[-self.max_recent_errors:]
        
        # Update min/max times
        stats.min_time = min(stats.min_time, metric.duration)
        stats.max_time = max(stats.max_time, metric.duration)
    
    def get_agent_status(self) -> Dict[str, Dict[str, any]]:
        """Get status summary for all agents"""
        status = {}
        
        for agent_name, stats in self.stats.items():
            status[agent_name] = {
                'total_executions': stats.total_executions,
                'success_rate': round(stats.success_rate * 100, 1),
                'average_time': round(stats.average_time, 2),
                'min_time': round(stats.min_time, 2) if stats.min_time != float('inf') else 0,
                'max_time': round(stats.max_time, 2),
                'recent_errors': len(stats.recent_errors),
                'status': self._get_health_status(stats)
            }
        
        return status
    
    def _get_health_status(self, stats: AgentStats) -> str:
        """Determine health status based on stats"""
        if stats.total_executions == 0:
            return 'UNKNOWN'
        
        if stats.success_rate >= 0.9:
            return 'HEALTHY'
        elif stats.success_rate >= 0.7:
            return 'WARNING'
        else:
            return 'CRITICAL'
    
    def get_performance_summary(self) -> Dict[str, any]:
        """Get overall performance summary"""
        if not self.stats:
            return {'status': 'NO_DATA'}
        
        total_executions = sum(s.total_executions for s in self.stats.values())
        total_successful = sum(s.successful_executions for s in self.stats.values())
        total_time = sum(s.total_time for s in self.stats.values())
        
        return {
            'total_executions': total_executions,
            'overall_success_rate': round((total_successful / total_executions * 100) if total_executions > 0 else 0, 1),
            'total_processing_time': round(total_time, 2),
            'average_execution_time': round(total_time / total_executions if total_executions > 0 else 0, 2),
            'agents_monitored': len(self.stats),
            'healthy_agents': len([s for s in self.stats.values() if self._get_health_status(s) == 'HEALTHY']),
            'timestamp': datetime.now().isoformat()
        }

# Global monitor instance
AGENT_MONITOR = AgentMonitor()