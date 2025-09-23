"""Scenario parsing and diagram generation coordination"""
import re
from typing import List, Tuple, Dict, Any

class ScenarioParser:
    """Handles parsing scenarios from report content and coordinating diagram generation"""
    
    def __init__(self):
        # Prioritized patterns - more specific first to avoid duplicates
        self.scenario_patterns = [
            r'<h[23]>\s*SCENARIO\s+([A-Z]):\s*([^<]+)</h[23]>',  # HTML: <h2>SCENARIO A: Title</h2>
            r'SCENARIO\s+([A-Z]):\s*([^\n<]+)',  # Plain: SCENARIO A: Title
            r'(\d+\.\d+)\s+SCENARIO\s+([A-Z]):\s*([^\n<]+)',  # Numbered: 4.1 SCENARIO A: Title
        ]
    
    def find_scenarios(self, report_content: str) -> List[Tuple[str, str]]:
        """Find all unique scenarios in report content"""
        scenarios_found = []
        processed_ids = set()
        
        print("🔍 Parsing scenarios from report content...")
        
        # Try each pattern in priority order
        for pattern in self.scenario_patterns:
            matches = re.finditer(pattern, report_content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) == 2:  # SCENARIO A: Title format
                    scenario_id = match.group(1).upper()
                    scenario_title = match.group(2)
                elif len(match.groups()) == 3:  # 4.1 SCENARIO A: Title format
                    scenario_id = match.group(2).upper()
                    scenario_title = match.group(3)
                else:
                    continue
                
                # Skip if already processed
                if scenario_id in processed_ids:
                    continue
                
                # Clean title
                clean_title = self._clean_scenario_title(scenario_title)
                scenarios_found.append((scenario_id, clean_title))
                processed_ids.add(scenario_id)
        
        # Fallback: look for placeholders if no scenarios found
        if not scenarios_found:
            placeholders = re.findall(r'\[DIAGRAM_PLACEHOLDER_SCENARIO_([A-Z0-9]+)\]', report_content)
            scenarios_found = [(pid.upper(), f"Scenario {pid}") for pid in placeholders if pid.upper() not in processed_ids]
        
        print(f"Found unique scenarios: {scenarios_found}")
        return scenarios_found
    
    def _clean_scenario_title(self, title: str) -> str:
        """Clean scenario title from HTML entities and tags"""
        # Remove HTML tags
        title = re.sub(r'<[^>]+>', '', title)
        
        # Fix HTML entities
        entities = {
            '&amp;#39;': "'", '&amp;': '&', '&lt;': '<', 
            '&gt;': '>', '&quot;': '"', '&#39;': "'"
        }
        for entity, replacement in entities.items():
            title = title.replace(entity, replacement)
        
        return title.strip()
    
    def extract_scenario_content(self, report_content: str, scenario_id: str, scenario_title: str) -> str:
        """Extract detailed scenario content for diagram generation"""
        # Find placeholder position first
        placeholder = f'[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id}]'
        placeholder_pos = report_content.find(placeholder)
        
        if placeholder_pos > 0:
            # Extract content before placeholder - increased window
            search_start = max(0, placeholder_pos - 5000)
            content_before = report_content[search_start:placeholder_pos]
            
            # Clean HTML entities and tags
            content_before = re.sub(r'&[a-zA-Z0-9#]+;', '', content_before)
            content_before = re.sub(r'<[^>]+>', '', content_before)
            
            # Find scenario start
            scenario_patterns = [
                rf'<h[23]>[^<]*SCENARIO\s+{re.escape(scenario_id)}[^<]*</h[23]>',
                rf'SCENARIO\s+{re.escape(scenario_id)}:[^\n]*',
                rf'\d+\.\s*SCENARIO\s+{re.escape(scenario_id)}:[^\n]*'
            ]
            
            for pattern in scenario_patterns:
                matches = list(re.finditer(pattern, content_before, re.IGNORECASE))
                if matches:
                    last_match = matches[-1]
                    scenario_start = search_start + last_match.start()
                    return report_content[scenario_start:placeholder_pos].strip()
            
            # Fallback: return content before placeholder - increased size
            return content_before[-3000:].strip()
        
        # Final fallback
        return f"Scenario {scenario_id}: {scenario_title}"
    
    def replace_placeholders(self, report_content: str, scenario_id: str, diagram_html: str) -> str:
        """Replace diagram placeholders with actual diagrams"""
        placeholder_patterns = [
            f'[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id}]',
            f'[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id.upper()}]',
            f'[DIAGRAM_PLACEHOLDER_SCENARIO_{scenario_id.lower()}]'
        ]
        
        replaced = False
        for placeholder in placeholder_patterns:
            if placeholder in report_content:
                report_content = report_content.replace(placeholder, diagram_html)
                replaced = True
                break
        
        # If no placeholder found, insert after scenario title
        if not replaced:
            scenario_pattern = rf"SCENARIO\s+{re.escape(scenario_id)}[^\n]*"
            match = re.search(scenario_pattern, report_content, re.IGNORECASE)
            if match:
                insert_pos = match.end()
                report_content = report_content[:insert_pos] + "\n" + diagram_html + report_content[insert_pos:]
        
        return report_content