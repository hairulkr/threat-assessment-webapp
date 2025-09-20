from typing import Dict, Any, List
from local_mcp_server import LocalMermaidServer

class MermaidMCPClient:
    """Client for local Mermaid server integration"""
    
    def __init__(self):
        self.server = LocalMermaidServer()
        self.connected = True
    
    async def start_server(self):
        """Start the local Mermaid server"""
        print("✅ Local Mermaid server ready")
        return True
    
    async def generate_diagram(self, diagram_type: str, content: str, threats: List[Dict[str, Any]] = None) -> str:
        """Generate diagram using local server"""
        
        try:
            return self.server.generate_diagram(diagram_type, content, threats or [])
        except Exception as e:
            print(f"Local server failed: {e}")
            return self._fallback_diagram(diagram_type, content)
    
    def _fallback_diagram(self, diagram_type: str, content: str) -> str:
        """Fallback diagram generation if MCP fails"""
        if diagram_type == "attack_flow":
            return """graph TD
    A[Attacker] --> B[Reconnaissance]
    B --> C[Initial Access]
    C --> D[Execution]
    D --> E[Persistence]
    E --> F[Privilege Escalation]
    F --> G[Data Exfiltration]
    
    classDef critical fill:#ff1744,color:#fff
    classDef high fill:#ff5722,color:#fff
    
    class C,F,G critical
    class D,E high"""
        
        elif diagram_type == "mitre_matrix":
            return """graph LR
    subgraph "Initial Access"
        T1190[Exploit Public Application]
        T1566[Phishing]
    end
    
    subgraph "Execution"
        T1059[Command Interpreter]
        T1203[Client Execution]
    end
    
    classDef technique fill:#3498db,color:#fff
    class T1190,T1566,T1059,T1203 technique"""
        
        return "graph TD\n    A[Fallback Diagram]"
    
    async def close(self):
        """Close local server connection"""
        self.connected = False
        print("🔌 Local server closed")