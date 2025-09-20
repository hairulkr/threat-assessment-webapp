"""
Local MCP-style Mermaid server implementation
No external dependencies required
"""

import json
from typing import Dict, Any, List

class LocalMermaidServer:
    """Local implementation of Mermaid diagram generation"""
    
    def __init__(self):
        self.templates = {
            "attack_flow": self._attack_flow_template,
            "mitre_matrix": self._mitre_matrix_template,
            "kill_chain": self._kill_chain_template,
            "data_flow": self._data_flow_template
        }
    
    def _attack_flow_template(self, context: str, threats: List[Dict]) -> str:
        """Professional attack flow template"""
        
        # Extract threat types from context
        has_sql = any('sql' in t.get('title', '').lower() for t in threats)
        has_xss = any('xss' in t.get('title', '').lower() for t in threats)
        has_rce = any('rce' in t.get('title', '').lower() or 'execution' in t.get('title', '').lower() for t in threats)
        
        mermaid = """graph TD
    A[🎯 Target System] --> B[🔍 Reconnaissance - T1595]
    B --> C[📡 Network Scanning - T1046]
    C --> D[🚪 Initial Access]
    
    subgraph "Attack Vectors"
"""
        
        if has_sql:
            mermaid += "        E1[💉 SQL Injection - T1190]\n"
            mermaid += "        D --> E1\n        E1 --> F[📊 Database Access]\n"
        
        if has_xss:
            mermaid += "        E2[🔗 Cross-Site Scripting - T1059]\n"
            mermaid += "        D --> E2\n        E2 --> G[🍪 Session Hijacking]\n"
        
        if has_rce:
            mermaid += "        E3[⚡ Remote Code Execution - T1190]\n"
            mermaid += "        D --> E3\n        E3 --> H[🖥️ System Access]\n"
        
        mermaid += """    end
    
    F --> I[🔒 Persistence - T1053]
    G --> I
    H --> I
    I --> J[⬆️ Privilege Escalation - T1068]
    J --> K[🔄 Lateral Movement - T1021]
    K --> L[📤 Data Exfiltration - T1041]
    
    classDef critical fill:#dc3545,stroke:#721c24,color:#fff
    classDef high fill:#fd7e14,stroke:#fd7e14,color:#fff
    classDef medium fill:#ffc107,stroke:#d39e00,color:#000
    classDef mitre fill:#6f42c1,stroke:#59359a,color:#fff
    
    class E1,E3,J,L critical
    class E2,I,K high
    class B,C,F,G,H medium
    class A mitre"""
        
        return mermaid
    
    def _mitre_matrix_template(self, context: str, threats: List[Dict]) -> str:
        """MITRE ATT&CK matrix template"""
        
        return """graph LR
    subgraph "Initial Access"
        T1190[T1190: Exploit Public-Facing Application]
        T1566[T1566: Phishing]
    end
    
    subgraph "Execution"
        T1059[T1059: Command and Scripting Interpreter]
        T1203[T1203: Exploitation for Client Execution]
    end
    
    subgraph "Persistence"
        T1053[T1053: Scheduled Task/Job]
        T1547[T1547: Boot or Logon Autostart Execution]
    end
    
    subgraph "Privilege Escalation"
        T1068[T1068: Exploitation for Privilege Escalation]
        T1055[T1055: Process Injection]
    end
    
    subgraph "Exfiltration"
        T1041[T1041: Exfiltration Over C2 Channel]
        T1020[T1020: Automated Exfiltration]
    end
    
    Threat1[SQL Injection] --> T1190
    Threat2[XSS Attack] --> T1059
    Threat3[Buffer Overflow] --> T1068
    Threat4[Malware] --> T1053
    
    classDef tactic fill:#2c3e50,color:#fff
    classDef technique fill:#3498db,color:#fff
    classDef threat fill:#e74c3c,color:#fff
    
    class T1190,T1566,T1059,T1203,T1053,T1547,T1068,T1055,T1041,T1020 technique
    class Threat1,Threat2,Threat3,Threat4 threat"""
    
    def _kill_chain_template(self, context: str, threats: List[Dict]) -> str:
        """Cyber kill chain template"""
        
        return """graph TD
    A[🔍 Reconnaissance] --> B[🔨 Weaponization]
    B --> C[📧 Delivery]
    C --> D[💥 Exploitation]
    D --> E[📥 Installation]
    E --> F[🎮 Command & Control]
    F --> G[🎯 Actions on Objectives]
    
    A --> A1[Network Scanning]
    A --> A2[OSINT Gathering]
    A --> A3[Social Engineering Recon]
    
    C --> C1[Phishing Email]
    C --> C2[Malicious Website]
    C --> C3[USB Drop Attack]
    
    D --> D1[Exploit CVE]
    D --> D2[Social Engineering]
    D --> D3[Password Attack]
    
    G --> G1[Data Theft]
    G --> G2[System Disruption]
    G --> G3[Ransomware Deployment]
    
    classDef phase fill:#2c3e50,color:#fff
    classDef action fill:#e67e22,color:#fff
    classDef objective fill:#c0392b,color:#fff
    
    class A,B,C,D,E,F,G phase
    class A1,A2,A3,C1,C2,C3,D1,D2,D3 action
    class G1,G2,G3 objective"""
    
    def _data_flow_template(self, context: str, threats: List[Dict]) -> str:
        """Data flow diagram template"""
        
        return """graph LR
    User[👤 User] --> Browser[🌐 Browser]
    Browser --> WAF[🛡️ Web Application Firewall]
    WAF --> LB[⚖️ Load Balancer]
    LB --> WebApp[📱 Web Application]
    WebApp --> API[🔌 API Gateway]
    API --> Auth[🔐 Authentication Service]
    API --> App[⚙️ Application Server]
    App --> DB[(💾 Database)]
    DB --> Backup[(💿 Backup Storage)]
    
    subgraph "DMZ"
        WAF
        LB
    end
    
    subgraph "Internal Network"
        WebApp
        API
        Auth
        App
    end
    
    subgraph "Data Layer"
        DB
        Backup
    end
    
    classDef external fill:#e3f2fd,stroke:#1976d2
    classDef dmz fill:#fff3e0,stroke:#f57c00
    classDef internal fill:#f3e5f5,stroke:#7b1fa2
    classDef data fill:#e8f5e8,stroke:#388e3c
    
    class User,Browser external
    class WAF,LB dmz
    class WebApp,API,Auth,App internal
    class DB,Backup data"""
    
    def generate_diagram(self, diagram_type: str, context: str, threats: List[Dict] = None) -> str:
        """Generate diagram using local templates"""
        
        if diagram_type in self.templates:
            return self.templates[diagram_type](context, threats or [])
        else:
            return "graph TD\n    A[Unknown Diagram Type]"