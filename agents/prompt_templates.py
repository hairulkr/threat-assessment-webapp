"""Standardized prompt templates for consistent LLM output"""

class PromptTemplates:
    """Centralized prompt templates with model-specific optimizations"""
    
    @staticmethod
    def get_comprehensive_report_prompt(all_data: dict) -> str:
        """Generate the main threat modeling report prompt"""
        return f"""Generate a technical threat modeling report based on the collected threat intelligence data.

THREAT INTELLIGENCE FINDINGS:
Product: {all_data.get('product_name', 'Unknown')}

17-SOURCE INTELLIGENCE DATA:
{PromptTemplates._format_threat_data(all_data.get('threats', []))}

THREAT CONTEXT:
{PromptTemplates._format_context_data(all_data.get('threat_context', {}))}

RISK ASSESSMENT:
{PromptTemplates._format_risk_data(all_data.get('risks', {}))}

Create a threat modeling report with these sections:

1. EXECUTIVE SUMMARY
   - Key vulnerabilities found from threat intelligence
   - Critical risks identified
   - Immediate actions needed

2. THREAT INTELLIGENCE ANALYSIS
   - **Recent Attack Trends:** Based on threat context and intelligence sources
   - **CVE Analysis:** Analysis of specific CVEs found with CVSS scores and exploit status

3. ATTACK SCENARIOS (EXACTLY 3)
   Analyze the threat intelligence findings above and create exactly 3 different attack scenarios.
   Each scenario should be based on actual CVE/vulnerability findings.
   
   Structure each scenario as:
   **SCENARIO [A/B/C]: [Attack Type based on CVE findings]**
   
   For each scenario:
   - Base the attack on specific CVE(s) from the findings
   - Create realistic attack phases based on the vulnerability type
   - Map to appropriate MITRE ATT&CK techniques
   - Include technical details from the threat intelligence
   
   Do NOT include any diagram placeholders - diagrams will be added automatically
   
   **For each phase include:**
   - Specific technical implementation details and commands
   - Tools and techniques used in recent real-world attacks
   - Detection signatures, IOCs, and monitoring recommendations
   - Mitigation strategies and security controls
   - Risk assessment and business impact analysis

4. SECURITY CONTROLS & MITIGATIONS
   Map specific controls to attack steps with implementation details.
   
   Include for each control:
   - Technical implementation details and configuration requirements
   - Administrative and procedural controls
   - Detection and monitoring capabilities
   - Implementation priority based on threat severity and business impact
   - Cost-benefit analysis and resource requirements
   - Effectiveness rating against identified attack vectors

{PromptTemplates._get_formatting_instructions()}"""
    
    @staticmethod
    def _format_threat_data(threats: list) -> str:
        """Format threat data for prompt inclusion"""
        import json
        return json.dumps([{
            'cve_id': t.get('cve_id', 'N/A'),
            'title': t.get('title', ''),
            'severity': t.get('severity', ''),
            'cvss_score': t.get('cvss_score', 0),
            'source': t.get('source', ''),
            'description': t.get('description', ''),
            'exploit_available': t.get('exploit_available', False)
        } for t in threats], indent=2)
    
    @staticmethod
    def _format_context_data(context: dict) -> str:
        """Format context data for prompt inclusion"""
        import json
        return json.dumps(context, indent=2)
    
    @staticmethod
    def _format_risk_data(risks: dict) -> str:
        """Format risk data for prompt inclusion"""
        import json
        return json.dumps(risks, indent=2)
    
    @staticmethod
    def _get_formatting_instructions() -> str:
        """Get consistent formatting instructions for all LLMs"""
        return """
FORMAT REQUIREMENTS:
- Use HTML tags for structure: <h1>, <h2>, <h3>, <p>, <ul>, <li>, <ol>, <strong>
- Use <span class="critical"> for high-risk items
- Use <span class="mitre"> for MITRE technique references
- NO markdown syntax (**, ##, etc.)
- Properly close all HTML tags
- Use consistent heading hierarchy
- Escape special characters in content

CRITICAL: Return ONLY the HTML content. No wrapper tags, explanations, or markdown code blocks."""
    
    @staticmethod
    def get_model_specific_suffix(model_type: str) -> str:
        """Get model-specific formatting hints"""
        suffixes = {
            'gpt': "\\n\\nIMPORTANT: Return clean HTML only. No markdown syntax.",
            'claude': "\\n\\nOutput format: Valid HTML with proper tag closure.",
            'gemini': "\\n\\nGenerate structured HTML. Avoid mixing HTML and markdown."
        }
        return suffixes.get(model_type.lower(), suffixes['gpt'])