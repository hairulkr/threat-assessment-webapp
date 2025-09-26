"""Simplified threat modeling report generation"""
import os
import asyncio
from datetime import datetime
from typing import Dict, Any

class SimpleReportAgent:
    """Simplified LLM-powered threat modeling report generation"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.reports_dir = "reports"
        os.makedirs(self.reports_dir, exist_ok=True)
    
    async def generate_comprehensive_report(self, all_data: Dict[str, Any]) -> str:
        """Generate complete threat modeling report with single LLM call"""
        
        product_name = all_data.get('product_name', 'Unknown Product')
        threats = all_data.get('threats', [])
        
        # Create simple threat summary
        threat_list = []
        for threat in threats[:10]:
            cve_id = threat.get('cve_id', 'N/A')
            title = threat.get('title', 'Unknown')
            severity = threat.get('severity', 'MEDIUM')
            threat_list.append(f"- {cve_id}: {title} ({severity})")
        
        # Single comprehensive prompt
        prompt = f"""Generate a complete HTML threat modeling report for {product_name}.

THREATS FOUND:
{chr(10).join(threat_list)}

Generate a professional HTML report with:
1. Executive Summary
2. Threat Analysis with CVE details
3. Attack Scenarios (2-3 scenarios)
4. Recommendations

Use proper HTML tags and include:
- <span class="cve-badge">{cve_id}</span> for CVE references
- <span class="mitre-badge">{technique}</span> for MITRE techniques
- <span class="severity-{severity}">{severity}</span> for severity levels

Return ONLY the HTML content (no markdown, no code blocks)."""

        try:
            report_content = await asyncio.wait_for(
                self.llm.generate(prompt, max_tokens=4000),
                timeout=120
            )
            
            # Simple cleanup
            report_content = report_content.strip()
            if report_content.startswith('```html'):
                report_content = report_content.replace('```html', '').replace('```', '')
            
            print(f"✅ SIMPLE REPORT GENERATED: {len(report_content)} characters")
            return report_content
            
        except Exception as e:
            print(f"⚠️ Report generation failed: {e}")
            return self._generate_fallback_report(product_name, threats)
    
    def _generate_fallback_report(self, product_name: str, threats: list) -> str:
        """Simple fallback report"""
        threat_count = len(threats)
        
        return f"""
        <h1>Threat Assessment Report - {product_name}</h1>
        
        <h2>Executive Summary</h2>
        <p>This assessment identified <strong>{threat_count} potential threats</strong> for {product_name}.</p>
        
        <h2>Key Findings</h2>
        <ul>
        {"".join([f'<li><span class="cve-badge">{t.get("cve_id", "N/A")}</span> - {t.get("title", "Unknown")} (<span class="severity-{t.get("severity", "MEDIUM")}">{t.get("severity", "MEDIUM")}</span>)</li>' for t in threats[:5]])}
        </ul>
        
        <h2>Recommendations</h2>
        <ul>
        <li>Keep software updated with latest security patches</li>
        <li>Implement network segmentation and monitoring</li>
        <li>Deploy multi-factor authentication</li>
        <li>Conduct regular security assessments</li>
        </ul>
        """
    
    def save_html_report(self, report_content: str, product_name: str) -> str:
        """Save report with simple HTML template"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_product_name = product_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
        filename = f"{safe_product_name}_ThreatModel_{timestamp}.html"
        filepath = os.path.join(self.reports_dir, filename)
        
        # Simple HTML template
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Report - {product_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #2563eb; border-bottom: 2px solid #2563eb; }}
        h2 {{ color: #374151; margin-top: 30px; }}
        .cve-badge {{ background: #dc2626; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.9em; }}
        .mitre-badge {{ background: #2563eb; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.9em; }}
        .severity-CRITICAL {{ background: #991b1b; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
        .severity-HIGH {{ background: #dc2626; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
        .severity-MEDIUM {{ background: #d97706; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
        .severity-LOW {{ background: #059669; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    {report_content}
</body>
</html>"""
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_template)
            
            print(f"📄 Simple HTML report saved: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"Error creating HTML report: {e}")
            return f"HTML report creation failed: {e}"