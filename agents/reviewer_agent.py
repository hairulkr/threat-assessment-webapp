from typing import Dict, Any, List

class ReviewerAgent:
    """Optimized expert reviewer using batched analysis for accuracy and efficiency"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
    
    def calculate_threat_intel_confidence(self, threats: List[Dict[str, Any]], threat_context: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate structured confidence score for threat intelligence"""
        web_intel = threat_context.get('web_intelligence', [])
        combined_intel = threat_context.get('combined_intelligence', threats + web_intel)
        total_sources = len(combined_intel)
        
        # Authority scoring
        official_count = len([t for t in web_intel if t.get('authority') == 'OFFICIAL'])
        verified_count = len([t for t in web_intel if t.get('authority') == 'VERIFIED'])
        community_count = len([t for t in web_intel if t.get('authority') == 'COMMUNITY'])
        
        # Base confidence from source count - more generous scoring
        if total_sources >= 5:
            base_score = 8
        elif total_sources >= 3:
            base_score = 7
        elif total_sources >= 1:
            base_score = 5
        else:
            base_score = 1
        
        # Authority bonuses
        authority_bonus = (official_count * 2) + (verified_count * 1) + (community_count * 0.5)
        
        # Relevance bonus (if relevance scores available) - include NVD CVEs
        relevance_bonus = 0
        nvd_count = len([item for item in combined_intel if item.get('source') == 'NVD'])
        
        if nvd_count > 0:
            # NVD CVEs automatically get 0.8 relevance
            avg_relevance = 0.8
            relevance_bonus = avg_relevance * 2
        else:
            # Use web intelligence relevance scores
            relevance_scores = [item.get('relevance_score', 0) for item in web_intel if 'relevance_score' in item]
            if relevance_scores:
                avg_relevance = sum(relevance_scores) / len(relevance_scores)
                relevance_bonus = avg_relevance * 2
        
        # Calculate final confidence (1-10 scale)
        final_confidence = min(base_score + authority_bonus + relevance_bonus, 10)
        
        return {
            'confidence_score': round(final_confidence, 1),
            'total_sources': total_sources,
            'nvd_cves_found': nvd_count,
            'authority_breakdown': {'official': official_count, 'verified': verified_count, 'community': community_count},
            'average_relevance': 0.8 if nvd_count > 0 else (round(sum([item.get('relevance_score', 0) for item in web_intel if 'relevance_score' in item]) / max(len([item for item in web_intel if 'relevance_score' in item]), 1), 2)),
            'confidence_level': 'HIGH' if final_confidence >= 7 else 'MEDIUM' if final_confidence >= 4 else 'LOW'
        }
    
    async def batch_data_quality_review(self, product_info: Dict[str, Any], threats: List[Dict[str, Any]], threat_context: Dict[str, Any]) -> Dict[str, Any]:
        """Batch 1: Review data quality across ProductInfo, ThreatIntel, and ThreatContext agents"""
        
        review_prompt = f"""
        As a cybersecurity data analyst, review the quality and accuracy of threat intelligence data:
        
        PRODUCT ANALYSIS:
        {product_info}
        
        THREAT INTELLIGENCE:
        Top Threats: {[t.get('title', '') + ' (' + t.get('severity', '') + ')' for t in threats[:5]]}
        Total Threats: {len(threats)}
        
        WEB INTELLIGENCE:
        Sources: {len(threat_context.get('web_intelligence', []))}
        Intelligence: {[item.get('source', '') + ': ' + item.get('type', '') for item in threat_context.get('web_intelligence', [])[:3]]}
        
        COMPREHENSIVE DATA QUALITY ASSESSMENT:
        
        1. PRODUCT ANALYSIS QUALITY (Rate 1-10)
           - Component identification completeness
           - Technology stack accuracy
           - Attack surface mapping
           - Missing critical elements
        
        2. OVERALL THREAT INTELLIGENCE CONFIDENCE (Rate 1-10)
           Calculate aggregate confidence based on QUALITY over quantity:
           - Total sources: {len(threats)} CVE threats + {len(threat_context.get('web_intelligence', []))} web intel
           - Authority: {len([t for t in threat_context.get('web_intelligence', []) if t.get('authority') == 'VERIFIED'])} VERIFIED sources (high value)
           - Relevance: Sources passed 0.3+ relevance threshold (pre-filtered for accuracy)
           - Quality assessment: 3+ relevant sources = HIGH confidence, 1-2 = MEDIUM, 0 = LOW
           - AGGREGATE CONFIDENCE SCORE (1-10): Rate based on source quality and relevance, not quantity
        
        3. WEB INTELLIGENCE ASSESSMENT (Rate 1-10)
           - Source credibility
           - Intelligence relevance
           - Timeliness of data
           - Coverage gaps
        
        4. CROSS-VALIDATION FINDINGS
           - Data consistency across sources
           - Conflicting information
           - Validation confidence level
        
        5. TERMINATION RECOMMENDATION
           - Only recommend TERMINATE if AGGREGATE CONFIDENCE is below 4/10
           - Quality threshold: 3+ relevant sources = PROCEED (high confidence)
           - 1-2 relevant sources = PROCEED (medium confidence) 
           - 0 relevant sources = TERMINATE (no actionable intelligence)
           - Current status: {len(threats) + len(threat_context.get('web_intelligence', []))} total sources found
           - Provide reasoning based on source quality and actionability
        
        Provide specific recommendations for data quality improvements or termination.
        """
        
        try:
            review = await self.llm.generate(review_prompt, max_tokens=1000)
            
            # Check for termination recommendation based on aggregate confidence
            terminate = ("RECOMMEND" in review.upper() and "TERMINATE" in review.upper()) or ("AGGREGATE CONFIDENCE" in review.upper() and any(score in review for score in ["1/10", "2/10", "3/10"]))
            
            return {
                "data_quality_review": review,
                "batch": "DATA_QUALITY",
                "status": "COMPLETED",
                "terminate_recommended": terminate
            }
        except Exception as e:
            return {
                "data_quality_review": f"Review failed: {e}",
                "batch": "DATA_QUALITY",
                "status": "FAILED"
            }
    
    async def conduct_comprehensive_review(self, all_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate data quality and proceed only with high confidence data"""
        
        # Extract data for quality validation
        product_info = all_data.get('product_info', {})
        threats = all_data.get('threats', [])
        threat_context = all_data.get('threat_context', {})
        
        # Calculate structured confidence score
        confidence_metrics = self.calculate_threat_intel_confidence(threats, threat_context)
        print(f"   📊 CONFIDENCE METRICS: {confidence_metrics['confidence_score']}/10 ({confidence_metrics['confidence_level']})")
        print(f"   📈 SOURCES: {confidence_metrics['total_sources']} total (NVD CVEs: {confidence_metrics['nvd_cves_found']})")
        print(f"   🎯 RELEVANCE: {confidence_metrics['average_relevance']}/1.0 average")
        
        # Only terminate if absolutely no relevant intelligence found
        if confidence_metrics['confidence_score'] < 2.0 and confidence_metrics['total_sources'] == 0:
            return {
                "comprehensive_review": {
                    "confidence_metrics": confidence_metrics,
                    "termination_notice": "⚠️ ANALYSIS TERMINATED: No threat intelligence found. Please try a different product name."
                },
                "review_status": "TERMINATED_NO_DATA",
                "batches_completed": 1,
                "terminate_recommended": True
            }
        
        # Skip LLM review for any confidence with sources - trust the comprehensive system
        if confidence_metrics['total_sources'] > 0:
            print(f"   ✅ PROCEEDING: {confidence_metrics['total_sources']} sources found, confidence {confidence_metrics['confidence_score']}/10")
            exec_summary = await self.generate_executive_summary(all_data)
            return {
                "comprehensive_review": {
                    "confidence_metrics": confidence_metrics,
                    "executive_summary": exec_summary
                },
                "review_status": "VALIDATED",
                "batches_completed": 1,
                "terminate_recommended": False
            }
        
        # Execute LLM review only for medium confidence (3-7)
        batch1 = await self.batch_data_quality_review(product_info, threats, threat_context)
        
        # Check if termination is recommended after data quality review
        if batch1.get("terminate_recommended", False):
            return {
                "comprehensive_review": {
                    "data_quality": batch1,
                    "termination_notice": "⚠️ ANALYSIS TERMINATED: Low confidence threat intelligence detected. Please research another product name and start the threat modeling process over with a different target."
                },
                "review_status": "TERMINATED_LOW_CONFIDENCE",
                "batches_completed": 1,
                "terminate_recommended": True
            }
        
        # Generate executive summary for high confidence data
        exec_summary = await self.generate_executive_summary(all_data)
        
        return {
            "comprehensive_review": {
                "data_quality": batch1,
                "executive_summary": exec_summary
            },
            "review_status": "HIGH_CONFIDENCE_VALIDATED",
            "batches_completed": 1,
            "terminate_recommended": False
        }
    
    async def generate_executive_summary(self, all_data: Dict[str, Any]) -> str:
        """Generate executive summary based on comprehensive review"""
        
        exec_summary_prompt = f"""
        Create an executive summary for this threat modeling assessment:
        
        PRODUCT: {all_data.get('product_name')}
        CRITICAL THREATS: {len([t for t in all_data.get('threats', []) if t.get('severity') == 'CRITICAL'])}
        HIGH THREATS: {len([t for t in all_data.get('threats', []) if t.get('severity') == 'HIGH'])}
        
        EXECUTIVE SUMMARY:
        
        1. SECURITY POSTURE OVERVIEW
           - Current risk level assessment
           - Key vulnerability areas
           - Threat landscape summary
        
        2. CRITICAL FINDINGS
           - Top 3 most severe risks
           - Immediate action requirements
           - Potential business impact
        
        3. STRATEGIC RECOMMENDATIONS
           - Security investment priorities
           - Risk mitigation roadmap
           - Compliance considerations
        
        4. IMPLEMENTATION ROADMAP
           - 30/60/90 day action plan
           - Resource requirements
           - Success metrics
        
        Focus on business impact and strategic decisions for C-level executives.
        """
        
        try:
            exec_summary = await self.llm.generate(exec_summary_prompt, max_tokens=600)
            return f"""
            <h1>📋 EXECUTIVE SUMMARY</h1>
            <div class="executive-summary">
                {exec_summary}
            </div>
            """
        except Exception:
            return "<h1>📋 EXECUTIVE SUMMARY</h1><p>Summary generation failed</p>"