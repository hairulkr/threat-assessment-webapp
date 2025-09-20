#!/usr/bin/env python3
"""
Multi-Agent Threat Modeling System
Simple local implementation for threat analysis
"""

import asyncio
import os
from gemini_client import GeminiClient
from agents import ProductInfoAgent, ThreatIntelAgent, RiskAnalysisAgent, ControlsAgent, ReportAgent
from agents.threat_context_agent import ThreatContextAgent
from agents.reviewer_agent import ReviewerAgent

from datetime import datetime

class ThreatModelingOrchestrator:
    """Coordinates all LLM-powered agents"""
    
    def __init__(self, api_key: str = None):
        self.llm = GeminiClient(api_key)
        self.product_agent = ProductInfoAgent(self.llm)
        self.threat_agent = ThreatIntelAgent(self.llm)
        self.threat_context_agent = ThreatContextAgent(self.llm)
        self.risk_agent = RiskAnalysisAgent(self.llm)
        self.controls_agent = ControlsAgent(self.llm)
        self.report_agent = ReportAgent(self.llm)
        self.reviewer_agent = ReviewerAgent(self.llm)
    
    async def run_threat_modeling(self, product_name: str) -> str:
        print(f"Starting comprehensive threat assessment for: {product_name}")
        
        # Collect all data from agents
        all_data = {
            "product_name": product_name,
            "timestamp": datetime.now().isoformat()
        }
        
        # Step 1: Gather product information (required for other steps)
        print("1. Gathering product information...")
        product_info = await self.product_agent.gather_info(product_name)
        all_data["product_info"] = product_info
        
        # Steps 2-4: Run threat intelligence and risk analysis in parallel
        print("2-4. Running parallel threat analysis...")
        
        # Create parallel tasks
        threat_task = self.threat_agent.fetch_recent_threats(product_info)
        
        # Wait for threats first (needed for context and risk analysis)
        threats = await threat_task
        all_data["threats"] = threats
        
        # Run context enrichment and risk analysis in parallel
        context_task = self.threat_context_agent.enrich_threat_report(product_name, threats)
        risk_task = self.risk_agent.analyze_risks(product_info, threats)
        
        threat_context, risks = await asyncio.gather(context_task, risk_task)
        all_data["threat_context"] = threat_context
        all_data["risks"] = risks
        
        # Step 4: Propose controls (depends on risks)
        print("4. Proposing security controls...")
        controls = await self.controls_agent.propose_controls(risks)
        all_data["controls"] = controls
        
        # Steps 5-6: Run expert review and report generation in parallel
        print("5-6. Finalizing analysis and generating report...")
        
        # Run review and report generation concurrently
        review_task = self.reviewer_agent.conduct_comprehensive_review(all_data)
        report_task = self.report_agent.generate_comprehensive_report(all_data)
        
        review_results, report_content = await asyncio.gather(review_task, report_task)
        
        # Check if analysis should be terminated
        if review_results.get("terminate_recommended", False):
            termination_msg = review_results.get("comprehensive_review", {}).get("termination_notice", "Analysis terminated due to low confidence data.")
            print(f"\n{termination_msg}")
            return None, None
        
        all_data["expert_review"] = review_results
        
        return report_content, all_data

async def main():
    api_key = os.getenv('GEMINI_API_KEY') or input("Enter Gemini API key: ").strip()
    orchestrator = ThreatModelingOrchestrator(api_key)
    
    while True:
        # Get user input with suggestions
        user_input = input("\nEnter product/system name for threat assessment (or 'quit' to exit): ").strip()
        
        if user_input.lower() in ['quit', 'exit', 'q']:
            print("👋 Goodbye!")
            return
            
        if not user_input:
            user_input = "Sample Web Application"
        
        # Get validated product name
        product_name = await orchestrator.product_agent.interactive_product_selection(user_input)
        
        if not product_name:
            print("\n🔄 Let's try again with a different product...")
            continue  # Re-prompt for new input
        
        # Confirm with user
        confirm = input(f"\nProceed with threat assessment for '{product_name}'? (y/n): ").strip().lower()
        if confirm != 'y':
            print("🔄 Let's try again...")
            continue  # Re-prompt for new input
        
        break  # Exit loop and proceed with threat modeling
    
    # Run comprehensive threat modeling
    report_content, all_data = await orchestrator.run_threat_modeling(product_name)
    
    # Check if analysis was terminated
    if report_content is None:
        print("\n🔄 Please try again with a different product name.")
        return
    
    # Save HTML report
    html_file = orchestrator.report_agent.save_html_report(report_content, product_name)
    
    print(f"\n=== COMPREHENSIVE THREAT ASSESSMENT COMPLETE ===")
    print(f"Product: {product_name}")
    print(f"HTML Report: {html_file}")
    print(f"\n{report_content}")
    print(f"\n📄 Open the HTML file in your browser to view the formatted report.")

if __name__ == "__main__":
    asyncio.run(main())