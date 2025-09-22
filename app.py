#!/usr/bin/env python3
"""
Streamlit Web App for Threat Modeling System
Lightweight demo version for POC
"""

import streamlit as st
import asyncio
import os
import sys
from datetime import datetime
import base64
import time
import streamlit.components.v1

# Import required modules
try:
    from daily_usage_tracker import DailyUsageTracker
except ImportError:
    # Fallback if module doesn't exist
    class DailyUsageTracker:
        def get_remaining_tries(self):
            return 10

# Import required modules with error handling
try:
    from llm_client import LLMClient, get_available_providers
    from gemini_client import GeminiClient  # Keep for backward compatibility
    from agents.product_info_agent import ProductInfoAgent
    from agents.threat_intel_agent import ThreatIntelAgent
    from agents.threat_context_agent import ThreatContextAgent
    from agents.risk_analysis_agent import RiskAnalysisAgent
    from agents.controls_agent import ControlsAgent
    from agents.report_agent import ReportAgent
    from agents.reviewer_agent import ReviewerAgent
except Exception as e:
    import streamlit as st
    st.error(f"Error importing modules: {e}")
    st.error("Please check if all required files are present in the repository.")
    st.stop()

# Page configuration
st.set_page_config(
    page_title="Cybersecurity Threat Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="auto"
)

# Custom CSS styles
st.markdown("""
<style>
    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        width: 280px !important;
        min-width: 280px !important;
    }
    
    /* Layout adjustments */
    .block-container {
        padding-top: 3rem !important;
        margin-top: 0rem !important;
    }
    .main > div {
        padding-top: 0rem !important;
    }
    
    /* Main header styling */
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin: 1rem 0 2rem 0;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    /* Red theme when threats found */
    .main-header.threats-found {
        background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%) !important;
        box-shadow: 0 4px 15px rgba(220, 38, 38, 0.3) !important;
    }
    
    /* Login container styling */
    .login-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin: 1rem 0 2rem 0;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    /* Progress bar styling */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #667eea, #764ba2);
    }
    
    /* Threat card styling */
    .threat-card {
        background: var(--secondary-background-color, #262730);
        color: var(--text-color, #fafafa);
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #dc2626;
        margin: 1rem 0;
        border: 1px solid #dc2626;
        box-shadow: 0 2px 8px rgba(220, 38, 38, 0.2);
    }
    
    [data-theme="light"] .threat-card {
        background: #fef2f2;
        color: #991b1b;
        border: 1px solid #fca5a5;
        border-left: 4px solid #dc2626;
    }
    
    /* Mobile responsive design */
    @media (max-width: 768px) {
        section[data-testid="stSidebar"] {
            display: none !important;
        }
        .main .block-container {
            padding: 0.5rem !important;
            margin-left: 0 !important;
        }
        .stButton > button {
            width: 100% !important;
            margin-bottom: 0.5rem !important;
            font-size: 0.8rem !important;
            padding: 0.4rem !important;
        }
        .stTextInput {
            width: 100% !important;
        }
        .stForm {
            padding: 0.5rem !important;
        }
        .main-header {
            padding: 1rem !important;
            margin-bottom: 1rem !important;
        }
        .main-header h1 {
            font-size: 1.3rem !important;
        }
        .main-header p {
            font-size: 0.9rem !important;
        }
    }
    
    @media (max-width: 480px) {
        .main .block-container {
            padding: 0.25rem !important;
        }
        h1 {
            font-size: 1.2rem !important;
        }
    }
</style>
""", unsafe_allow_html=True)

class ThreatModelingWebApp:
    """Streamlit web interface for threat modeling"""
    
    def __init__(self):
        self.setup_session_state()
        
    def setup_session_state(self):
        """Initialize session state variables"""
        defaults = {
            'assessment_complete': False,
            'report_content': None,
            'product_name': "",
            'all_data': None,
            'suggestions': [],
            'selected_product': "",
            'last_search': "",
            'valid_products': [],
            'assessment_running': False,
            'usage_tracker': DailyUsageTracker(),
            'show_methodology': False,
            'selected_llm_provider': 'gemini'
        }
        
        for key, value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = value
    
    async def run_assessment(self, product_name: str):
        """Run the threat assessment with progress tracking"""
        
        # Get selected LLM provider
        provider = st.session_state.get('selected_llm_provider', 'gemini')
        llm = LLMClient(provider)
        
        if not llm.is_available():
            st.error(f"❌ {provider.title()} API key not found in secrets or environment variables")
            return None, None
        
        # Initialize agents
        agents = {
            'product': ProductInfoAgent(llm),
            'threat': ThreatIntelAgent(llm),
            'context': ThreatContextAgent(llm),
            'risk': RiskAnalysisAgent(llm),
            'controls': ControlsAgent(llm),
            'report': ReportAgent(llm),
            'reviewer': ReviewerAgent(llm)
        }
        
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        status_box = st.empty()
        
        all_data = {
            "product_name": product_name,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            st.session_state.assessment_running = True
            
            # Step 1: Product Information
            status_text.markdown("**🔍 Step 1: Gathering product information...**")
            progress_bar.progress(10)
            
            with st.spinner("🔍 Analyzing product information..."):
                try:
                    product_info = await asyncio.wait_for(
                        agents['product'].gather_info(product_name), 
                        timeout=30
                    )
                except asyncio.TimeoutError:
                    st.error("Product analysis timed out. Please try again.")
                    return None, None
                except Exception as e:
                    st.error(f"Product analysis failed: {str(e)}")
                    return None, None
            
            status_box.success("Product information gathered successfully")
            all_data["product_info"] = product_info
            
            # Step 2: Threat Intelligence
            status_text.markdown("**🎯 Step 2: Fetching threat intelligence...**")
            progress_bar.progress(25)
            
            # Show detailed status during threat intelligence gathering
            status_container = st.container()
            with status_container:
                st.info("🔍 **Gathering from 17 threat intelligence sources:**")
                source_status = st.empty()
                
                # Update status during processing
                source_status.markdown("""
                - 🏢 **NVD CVE Database** - Searching official vulnerabilities...
                - 🐙 **GitHub Security Advisories** - Checking recent advisories...
                - 🏛️ **CISA Alerts** - Scanning government alerts...
                - 🔍 **Google CSE (12 sources)** - Comprehensive search across security databases...
                - 🏢 **Microsoft Security** - Vendor-specific advisories...
                """)
            
            try:
                threats = await asyncio.wait_for(
                    agents['threat'].fetch_recent_threats(product_info),
                    timeout=60
                )
            except asyncio.TimeoutError:
                st.error("Threat intelligence gathering timed out. Please try again.")
                return None, None
            except Exception as e:
                st.error(f"Threat intelligence failed: {str(e)}")
                return None, None
            
            # Clear status and show results
            source_status.empty()
            status_box.success(f"✅ **Threat Intelligence Complete:** {len(threats)} threats found from multiple sources")
            
            # Show source breakdown
            if threats:
                sources_found = list(set(t.get('source', 'Unknown') for t in threats))
                st.info(f"📊 **Sources:** {', '.join(sources_found[:5])}{'...' if len(sources_found) > 5 else ''}")
            all_data["threats"] = threats
            
            # Step 3: Threat Context & Risk Analysis
            status_text.markdown("**🌐 Step 3: Enriching with web intelligence...**")
            progress_bar.progress(40)
            
            # Show detailed web intelligence status
            web_status = st.empty()
            web_status.info("🌐 **Web Intelligence Sources:** Analyzing recent attack trends and similar tool compromises...")
            
            try:
                context_task = agents['context'].enrich_threat_report(product_name, threats)
                risk_task = agents['risk'].analyze_risks(product_info, threats)
                threat_context, risks = await asyncio.wait_for(
                    asyncio.gather(context_task, risk_task),
                    timeout=45
                )
            except asyncio.TimeoutError:
                st.error("Context analysis timed out. Please try again.")
                return None, None
            except Exception as e:
                st.error(f"Context analysis failed: {str(e)}")
                return None, None
            
            web_status.empty()
            status_box.success("✅ **Context Analysis Complete:** Attack trends and risk assessment finished")
            all_data["threat_context"] = threat_context
            all_data["risks"] = risks
            
            progress_bar.progress(60)
            
            # Step 4: Security Controls
            status_text.markdown("**🛡️ Step 4: Generating control recommendations...**")
            
            with st.spinner("🛡️ Generating security control recommendations..."):
                try:
                    controls = await asyncio.wait_for(
                        agents['controls'].propose_controls(risks),
                        timeout=30
                    )
                except asyncio.TimeoutError:
                    st.error("Control generation timed out. Please try again.")
                    return None, None
                except Exception as e:
                    st.error(f"Control generation failed: {str(e)}")
                    return None, None
            
            status_box.success("Security control framework established")
            all_data["controls"] = controls
            
            progress_bar.progress(75)
            
            # Step 5: Expert Review & Report Generation
            status_text.markdown("**📊 Step 5: Finalizing report generation...**")
            
            with st.spinner("📊 Conducting expert review and generating report..."):
                try:
                    review_task = agents['reviewer'].conduct_comprehensive_review(all_data)
                    report_task = agents['report'].generate_comprehensive_report(all_data)
                    review_results, report_content = await asyncio.wait_for(
                        asyncio.gather(review_task, report_task),
                        timeout=60
                    )
                except asyncio.TimeoutError:
                    st.error("Report generation timed out. Please try again.")
                    return None, None
                except Exception as e:
                    st.error(f"Report generation failed: {str(e)}")
                    return None, None
            
            status_box.success("Expert review and report generation completed")
            
            # Check for termination
            if review_results.get("terminate_recommended", False):
                progress_bar.progress(100)
                st.session_state.assessment_running = False
                status_text.markdown("**⚠️ Analysis terminated due to low confidence data**")
                st.warning("Analysis terminated: Low confidence threat intelligence detected. Please try a different product name.")
                return None, None
            
            all_data["expert_review"] = review_results
            
            progress_bar.progress(100)
            st.session_state.assessment_running = False
            status_text.markdown("**✅ Assessment completed successfully!**")
            status_box.success("Threat assessment report generated successfully")
            
            return report_content, all_data
            
        except Exception as e:
            st.session_state.assessment_running = False
            st.error(f"❌ Error during assessment: {str(e)}")
            # Log the full error for debugging
            import traceback
            print(f"Assessment error details: {traceback.format_exc()}")
            return None, None
        finally:
            # Ensure assessment_running is always reset
            st.session_state.assessment_running = False
    
    def display_threat_summary(self, all_data):
        """Display threat summary cards"""
        if not all_data or 'threats' not in all_data:
            return
            
        threats = all_data['threats']
        if not threats:
            st.info("No specific threats found for this product.")
            return
            
        st.subheader("🎯 Threat Summary")
        
        # Create columns for threat cards
        cols = st.columns(min(len(threats), 3))
        
        for i, threat in enumerate(threats[:3]):
            with cols[i % 3]:
                severity = threat.get('severity', 'UNKNOWN')
                severity_color = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠', 
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(severity, '⚪')
                
                with st.container():
                    st.markdown(f"### {severity_color} {threat.get('title', 'Unknown Threat')}")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Severity", threat.get('severity', 'Unknown'))
                    with col2:
                        st.metric("CVSS Score", threat.get('cvss_score', 'N/A'))
                    with col3:
                        st.metric("CVE ID", threat.get('cve_id', 'N/A'))
                    st.markdown("---")
    
    def create_pdf_download(self, content: str, filename: str):
        """Create PDF download with same format as threat assessment report"""
        # Create full HTML with same styling as the report display
        full_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #ffffff;
                    color: #262730;
                    margin: 0;
                    padding: 20px;
                    line-height: 1.6;
                }}
                .report-container {{
                    width: 100%;
                    margin: 0;
                    background: #ffffff;
                    padding: 15px;
                    box-sizing: border-box;
                }}
                h1 {{
                    color: #2c3e50;
                    border-bottom: 3px solid #667eea;
                    padding-bottom: 10px;
                    margin-bottom: 20px;
                }}
                h2 {{
                    color: #34495e;
                    margin-top: 30px;
                    border-left: 4px solid #667eea;
                    padding-left: 15px;
                }}
                h3 {{
                    color: #2c3e50;
                    margin-top: 25px;
                }}
                .critical {{
                    background-color: #fee;
                    color: #c53030;
                    padding: 2px 6px;
                    border-radius: 4px;
                    font-weight: bold;
                }}
                .mitre {{
                    background-color: #e6f3ff;
                    color: #1a365d;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: monospace;
                    font-weight: bold;
                }}
                .mermaid {{
                    text-align: center;
                    margin: 20px 0;
                    padding: 20px;
                    background-color: #f8f9fa;
                    border: 1px solid #dee2e6;
                    border-radius: 5px;
                }}
                .diagram-container {{
                    margin: 20px 0;
                    page-break-inside: avoid;
                }}
            </style>
            <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
        </head>
        <body>
            <div class="report-container">
                {content}
            </div>
            
            <script>
                mermaid.initialize({{
                    startOnLoad: true,
                    theme: 'default',
                    securityLevel: 'strict',
                    flowchart: {{
                        useMaxWidth: true,
                        htmlLabels: false
                    }}
                }});
            </script>
        </body>
        </html>
        """
        
        # Create download link with full HTML including diagrams
        b64 = base64.b64encode(full_html.encode()).decode()
        href = f'<a href="data:text/html;base64,{b64}" download="{filename}">📥 Download Complete Report (HTML)</a>'
        return href
    
    def check_rate_limit(self):
        """Simple rate limiting - 30 second cooldown"""
        if 'last_request' not in st.session_state:
            st.session_state.last_request = 0
        
        if time.time() - st.session_state.last_request < 30:
            remaining = int(30 - (time.time() - st.session_state.last_request))
            st.error(f"⏳ Please wait {remaining} seconds between assessments")
            return False
        
        st.session_state.last_request = time.time()
        return True
    
    def validate_input(self, product_name):
        """Enhanced input validation"""
        if not product_name:
            st.error("Please enter a product name")
            return False
        
        cleaned_name = " ".join(product_name.split())
        if len(cleaned_name) < 3:
            st.error("Product name must be at least 3 characters long")
            return False
            
        invalid_chars = ['<', '>', ';', '|', '&', '$', '#']
        if any(char in cleaned_name for char in invalid_chars):
            st.error("Product name contains invalid characters")
            return False
            
        if len(cleaned_name) > 100:
            st.error("Product name is too long (maximum 100 characters)")
            return False
            
        return True
    

    
    def check_authentication(self):
        """Password authentication with brute force protection"""
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        if 'login_attempts' not in st.session_state:
            st.session_state.login_attempts = 0
        if 'login_lockout_time' not in st.session_state:
            st.session_state.login_lockout_time = 0
        
        if not st.session_state.authenticated:
            st.markdown("""
            <div class="login-container">
                <h1>🔐 Cybersecurity Threat Assessment</h1>
                <p>Access Required - Enter Password</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Check if locked out
            current_time = time.time()
            if st.session_state.login_lockout_time > current_time:
                remaining_time = int(st.session_state.login_lockout_time - current_time)
                st.error(f"🔒 Too many failed attempts. Try again in {remaining_time} seconds.")
                st.stop()
            
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                with st.container(border=True):
                    password = st.text_input(
                        "Enter password:", 
                        type="password", 
                        key="login_password",
                        help="Enter your access password",
                        autocomplete="current-password"
                    )
                    
                    # Show remaining attempts
                    remaining_attempts = max(0, 5 - st.session_state.login_attempts)
                    if st.session_state.login_attempts > 0:
                        st.warning(f"⚠️ {remaining_attempts} attempts remaining")
                    
                    if st.button("🚀 Login", type="primary", use_container_width=True):
                        try:
                            app_password = st.secrets["APP_PASSWORD"]
                        except:
                            app_password = os.getenv('APP_PASSWORD', 'demo123')
                        
                        if password == app_password:
                            st.session_state.authenticated = True
                            st.session_state.login_attempts = 0  # Reset on success
                            st.rerun()
                        else:
                            st.session_state.login_attempts += 1
                            
                            if st.session_state.login_attempts >= 5:
                                # Lock out for 5 minutes
                                st.session_state.login_lockout_time = current_time + 300
                                st.error("🔒 Too many failed attempts. Locked out for 5 minutes.")
                            else:
                                remaining = 5 - st.session_state.login_attempts
                                st.error(f"❌ Invalid password. {remaining} attempts remaining.")
            st.stop()
    
    def main(self):
        """Main Streamlit application"""
        
        # Check authentication first
        self.check_authentication()
        
        # Header - keep consistent color
        header_class = "main-header"
        
        st.markdown(f"""
        <div class="{header_class}">
            <h1>🛡️ Cybersecurity Threat Assessment</h1>
            <p>AI-Powered Threat Modeling & Risk Analysis</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Sidebar
        with st.sidebar:
            st.header("⚙️ Configuration")
            
            # LLM Provider Selection
            st.subheader("🤖 AI Model Selection")
            
            providers = get_available_providers()
            
            # Create provider options with status
            provider_options = []
            provider_labels = []
            
            for provider_name, status in providers.items():
                provider_options.append(provider_name)
                status_icon = "✅" if "Available" in status["status"] else "❌"
                provider_labels.append(f"{status_icon} {provider_name.title()} ({status['model']})")
            
            # Provider selection
            if provider_options:
                selected_idx = 0
                current_provider = st.session_state.get('selected_llm_provider', 'gemini')
                if current_provider in provider_options:
                    selected_idx = provider_options.index(current_provider)
                
                selected_provider = st.selectbox(
                    "Select AI Provider:",
                    options=provider_options,
                    format_func=lambda x: provider_labels[provider_options.index(x)],
                    index=selected_idx,
                    key="llm_provider_select"
                )
                
                st.session_state.selected_llm_provider = selected_provider
                
                # Show detailed status for selected provider
                selected_status = providers[selected_provider]
                if "Available" in selected_status["status"]:
                    st.success(f"✅ {selected_status['provider']} Ready")
                    st.info(f"**Model:** {selected_status['model']}")
                else:
                    st.error(f"❌ {selected_status['provider']} - {selected_status['model']}")
                    if selected_provider == "gemini":
                        st.info("Add GEMINI_API_KEY to Streamlit secrets or environment variables")
                    elif selected_provider == "perplexity":
                        st.info("Add PERPLEXITY_API_KEY to Streamlit secrets or environment variables")
            else:
                st.error("❌ No LLM providers available")
            
            st.markdown("---")
            st.markdown("### 📋 Assessment Steps")
            
            steps = [
                "🔍 Product Analysis",
                "🎯 Multi-Agent Threat Intelligence", 
                "🌐 Accuracy Enhancement Analysis",
                "🛡️ Control Recommendations",
                "📊 Threat Modeling Report"
            ]
            
            for i, step in enumerate(steps, 1):
                st.markdown(f"{i}. {step}")
            
            # Usage tracker - dynamically updated
            usage_tracker = st.session_state.usage_tracker
            remaining_tries = usage_tracker.get_remaining_tries()
            
            st.markdown("### 🔒 Daily Assessment Quota")
            
            # Dynamic color based on remaining tries
            if remaining_tries > 5:
                bg_color = "#e8f5e8"
                border_color = "#4caf50"
                text_color = "#2e7d32"
            elif remaining_tries > 2:
                bg_color = "#fff3e0"
                border_color = "#ff9800"
                text_color = "#e65100"
            else:
                bg_color = "#ffe1e9"
                border_color = "#ffb1c7"
                text_color = "#9b2542"
            
            st.markdown(f"""
            <div style="
                background-color: {bg_color};
                border-radius: 4px;
                border: 1px solid {border_color};
                color: {text_color};
                padding: 16px;
                margin-top: 8px;
            ">
                <div><strong>{remaining_tries}</strong> assessments remaining</div>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("---")
            st.markdown("### 📚 Documentation")
            
            # Methodology documentation
            if st.button("📋 View Methodology", use_container_width=True):
                st.session_state.show_methodology = True
                st.rerun()
            
            st.markdown("---")
            st.markdown("### 🔍 Debug Tools")
            if st.button("🔍 Perplexity Debug", use_container_width=True):
                st.session_state.show_debug = True
                st.rerun()
            
            if st.session_state.get('show_methodology', False):
                if st.button("❌ Close Methodology", use_container_width=True):
                    st.session_state.show_methodology = False
                    st.rerun()
        
        # Check if methodology should be displayed
        if st.session_state.get('show_methodology', False):
            # Back to assessment link
            if st.button("← Back to Assessment", type="secondary"):
                st.session_state.show_methodology = False
                st.rerun()
            
            # Display methodology in full width
            st.header("📋 Methodology Documentation")
            
            methodology_path = os.path.join(os.path.dirname(__file__), "methodology.html")
            if os.path.exists(methodology_path):
                with open(methodology_path, 'r', encoding='utf-8') as f:
                    methodology_content = f.read()
                
                # Display methodology with dynamic height and scrolling enabled
                st.components.v1.html(methodology_content, height=1200, scrolling=True)
            else:
                st.error("Methodology file not found")
            
            return  # Exit early to show only methodology
        
        # Check if debug should be displayed
        if st.session_state.get('show_debug', False):
            if st.button("← Back to Assessment", type="secondary"):
                st.session_state.show_debug = False
                st.rerun()
            
            st.header("🔍 Perplexity API Debug")
            
            # API Key input
            api_key = st.text_input("Perplexity API Key", type="password", 
                                   value=os.getenv('PERPLEXITY_API_KEY', ''))
            
            if st.button("Test Perplexity API"):
                if not api_key:
                    st.error("Please enter your Perplexity API key")
                else:
                    import requests
                    import traceback
                    
                    with st.spinner("Testing Perplexity API..."):
                        
                        # Test 1: Direct API call
                        st.subheader("Test 1: Direct API Call")
                        try:
                            headers = {
                                "Authorization": f"Bearer {api_key}",
                                "Content-Type": "application/json"
                            }
                            
                            data = {
                                "model": "sonar-pro",
                                "messages": [
                                    {
                                        "role": "user",
                                        "content": "What are the latest cybersecurity threats in 2024?"
                                    }
                                ]
                            }
                            
                            st.write("📡 Making direct API call...")
                            response = requests.post(
                                "https://api.perplexity.ai/chat/completions", 
                                json=data, 
                                headers=headers, 
                                timeout=30
                            )
                            
                            st.write(f"Status Code: {response.status_code}")
                            
                            if response.status_code == 200:
                                result = response.json()
                                content = result["choices"][0]["message"]["content"]
                                st.success("✅ Direct API call successful!")
                                st.write("Response:", content[:200] + "...")
                            else:
                                st.error(f"❌ Direct API call failed: {response.status_code}")
                                st.write("Error response:", response.text)
                                
                        except Exception as e:
                            st.error(f"❌ Direct API call exception: {str(e)}")
                            st.write("Full traceback:", traceback.format_exc())
                        
                        # Test 2: LLMClient
                        st.subheader("Test 2: LLMClient")
                        try:
                            st.write("🔧 Creating LLMClient...")
                            client = LLMClient("perplexity", api_key)
                            
                            st.write("📊 Client status:", client.get_status())
                            
                            if client.is_available():
                                st.write("🚀 Calling generate method...")
                                
                                async def test_generate():
                                    return await client.generate("What are the top 3 cybersecurity threats?")
                                
                                result = asyncio.run(test_generate())
                                st.success("✅ LLMClient call successful!")
                                st.write("Response:", result)
                            else:
                                st.error("❌ LLMClient not available")
                                
                        except Exception as e:
                            st.error(f"❌ LLMClient exception: {str(e)}")
                            st.write("Full traceback:", traceback.format_exc())
            
            # Environment info
            st.subheader("Environment Information")
            st.write("Python version:", sys.version)
            st.write("Streamlit version:", st.__version__)
            st.write("Current working directory:", os.getcwd())
            
            # Show environment variables (without values)
            env_vars = [key for key in os.environ.keys() if 'PERPLEXITY' in key.upper()]
            st.write("Perplexity environment variables found:", env_vars)
            
            return  # Exit early to show only debug
        
        # Main content area
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.header("🎯 Product Assessment")
            
            # Product search and suggestion
            product_input = st.text_input(
                "Enter Product/System Name:",
                placeholder="e.g., Visual Studio Code, Apache Tomcat, WordPress",
                help="Enter the name of the software product you want to assess",
                key="product_search"
            )
            
            # CPE-based product suggestions
            if product_input and len(product_input) > 2:
                if ('suggestions' not in st.session_state or 
                    st.session_state.get('last_search') != product_input):
                    
                    try:
                        api_key = st.secrets["GEMINI_API_KEY"]
                    except:
                        api_key = os.getenv('GEMINI_API_KEY')
                    
                    provider = st.session_state.get('selected_llm_provider', 'gemini')
                    llm = LLMClient(provider)
                    if llm.is_available():
                        with st.status("🤖 AI is completing your input...", expanded=False):
                            product_agent = ProductInfoAgent(llm)
                            try:
                                raw_suggestions = asyncio.run(product_agent.smart_product_completion(product_input))
                                # Convert to dict format for consistency
                                if raw_suggestions and len(raw_suggestions) > 0:
                                    suggestions = [{'name': s, 'source': 'AI Completion'} for s in raw_suggestions if s and s != product_input]
                                else:
                                    suggestions = []
                            except Exception as e:
                                st.error(f"Error getting suggestions: {e}")
                                suggestions = []
                            st.session_state.suggestions = suggestions
                            st.session_state.last_search = product_input
                
                # Display suggestions if available
                if 'suggestions' in st.session_state and st.session_state.suggestions:
                    st.success(f"✅ **Found {len(st.session_state.suggestions)} product suggestions:**")
                    
                    # Display suggestions as clickable buttons
                    cols = st.columns(min(len(st.session_state.suggestions), 2))
                    for i, suggestion in enumerate(st.session_state.suggestions):
                        with cols[i % 2]:
                            # Handle both dict and string formats for backward compatibility
                            if isinstance(suggestion, dict):
                                name = suggestion['name']
                                source = suggestion.get('source', 'AI Completion')
                                button_text = f"🎯 {name}"
                                help_text = f"From {source}"
                            else:
                                name = suggestion
                                button_text = f"🎯 {name}"
                                help_text = "AI suggested product name"
                            
                            if st.button(
                                button_text,
                                key=f"suggestion_{i}",
                                use_container_width=True,
                                help=help_text
                            ):
                                st.session_state.selected_product = name
                                st.rerun()
                
                elif len(product_input) > 2:
                    st.info("💡 **No CVE data found for this product name**")
                    st.markdown("""
                    **Tip**: Try searching at [NVD CPE Search](https://nvd.nist.gov/products/cpe/search) for exact product names.
                    """)
            
            # Assessment form
            if product_input or st.session_state.get('selected_product'):
                with st.form("assessment_form"):
                    # Use selected product or user input
                    final_product = st.session_state.get('selected_product', product_input)
                    
                    # Show the product name that will be assessed
                    st.text_input(
                        "Product to assess:",
                        value=final_product,
                        disabled=True,
                        help="This is the product that will be assessed"
                    )
                    
                    col_a, col_b = st.columns([4, 1])
                    with col_a:
                        is_running = st.session_state.get('assessment_running', False)
                        button_text = "⏳ Processing Assessment..." if is_running else "🚀 Start Assessment"
                        submit_button = st.form_submit_button(
                            button_text,
                            type="primary",
                            disabled=is_running
                        )
                    with col_b:
                        example_button = st.form_submit_button(
                            "📝 Try Example",
                            disabled=st.session_state.get('assessment_running', False)
                        )
                    
                    product_name = final_product
            else:
                # Show example button when no input
                with st.form("example_form"):
                    st.info("Enter a product name above or try an example")
                    submit_button = False
                    example_button = st.form_submit_button(
                        "📝 Try Example: Visual Studio Code",
                        disabled=st.session_state.get('assessment_running', False)
                    )
                    product_name = None
            
            # Handle form submission
            if submit_button and product_name:
                # Prevent concurrent assessments
                if st.session_state.get('assessment_running', False):
                    st.warning("⏳ Assessment already in progress. Please wait for it to complete.")
                    st.stop()
                    
                # Clear selected product after using it
                if 'selected_product' in st.session_state:
                    del st.session_state['selected_product']
                if not self.check_rate_limit():
                    st.stop()
                if not self.validate_input(product_name):
                    st.stop()
                
                # Check daily limit using usage tracker
                usage_tracker = st.session_state.usage_tracker
                if usage_tracker.get_remaining_tries() <= 0:
                    st.error("🚫 Daily limit reached (10 assessments). Try again tomorrow.")
                    st.stop()
                
                # Reset assessment state before starting new one
                st.session_state.assessment_complete = False
                st.session_state.report_content = None
                st.session_state.all_data = None
                st.session_state.assessment_running = True
                st.session_state.product_name = product_name
                st.rerun()
            
            elif example_button:
                # Prevent concurrent assessments
                if st.session_state.get('assessment_running', False):
                    st.warning("⏳ Assessment already in progress. Please wait for it to complete.")
                    st.stop()
                    
                if not self.check_rate_limit():
                    st.stop()
                
                # Check daily limit using usage tracker
                usage_tracker = st.session_state.usage_tracker
                if usage_tracker.get_remaining_tries() <= 0:
                    st.error("🚫 Daily limit reached (10 assessments). Try again tomorrow.")
                    st.stop()
                
                # Reset assessment state before starting new one
                st.session_state.assessment_complete = False
                st.session_state.report_content = None
                st.session_state.all_data = None
                st.session_state.assessment_running = True
                st.session_state.product_name = "Visual Studio Code"
                st.rerun()
        
        with col2:
            st.header("ℹ️ About")
            with st.container(border=True):
                st.markdown("""
                **🎯 Latest Attack Intelligence:** Prioritizes most current attack patterns and threat actor campaigns from latest available sources
                
                **📊 17-Source Intelligence:** NVD CVE, GitHub Security, CISA Alerts, Google CSE (12 databases), Microsoft Security with authority weighting
                """)
                
                with st.expander("🔍 View More Details"):
                    st.markdown("""
                    **🔍 Scenario-Specific Modeling:**
                    - **Dynamic Scenario Types:** Remote Code Execution, Privilege Escalation, Data Exfiltration, Availability, Supply Chain attacks
                    - **Threat-Matched Attack Flows:** Each scenario gets unique attack flow diagrams based on actual threat intelligence
                    - **CVE-Based Analysis:** Reconnaissance → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Impact
                    
                    **🏆 Enhanced Intelligence:**
                    - **Multi-Agent Ranking:** CVE Agent (CVSS + recency), Exploit Agent (weaponization status), Authority Agent (source credibility), Relevance Agent (product matching)
                    - **Ensemble Scoring:** Authority weight × Recency factor × CVSS normalized × Relevance score
                    - **Priority Algorithm:** Official sources (3x weight) → Verified sources (2x) → Community (1x) with exploit availability boost
                    - **Accuracy Enhancement:** ThreatAccuracyEnhancer filters by exploit availability, patch status, attack complexity, detection difficulty
                    """)
            
            if st.session_state.assessment_complete:
                st.success("✅ Assessment Complete!")
                
                # Download button
                if st.session_state.report_content:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_product_name = st.session_state.product_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
                    filename = f"{safe_product_name}_assessment_{timestamp}.html"
                    
                    download_link = self.create_pdf_download(
                        st.session_state.report_content, 
                        filename
                    )
                    st.markdown(download_link, unsafe_allow_html=True)
        
        # Run assessment if in running state
        if st.session_state.get('assessment_running') and not st.session_state.get('assessment_complete'):
            product_name = st.session_state.get('product_name', '')
            usage_tracker = st.session_state.usage_tracker
            
            try:
                # Use asyncio.run with timeout wrapper
                async def run_with_timeout():
                    return await asyncio.wait_for(
                        self.run_assessment(product_name),
                        timeout=300  # 5 minute total timeout
                    )
                
                report_content, all_data = asyncio.run(run_with_timeout())
                
                if report_content and all_data:
                    # Increment usage after successful assessment
                    usage_tracker.increment_usage()
                    st.session_state.report_content = report_content
                    st.session_state.all_data = all_data
                    st.session_state.assessment_complete = True
                    st.session_state.assessment_running = False
                else:
                    # Assessment failed or was terminated
                    st.session_state.assessment_running = False
                    st.error("Assessment failed or was terminated. Please try again.")
            except asyncio.TimeoutError:
                st.session_state.assessment_running = False
                st.error("Assessment timed out after 5 minutes. Please try again with a different product.")
            except Exception as e:
                st.session_state.assessment_running = False
                st.error(f"Assessment error: {str(e)}")
                import traceback
                print(f"Full error trace: {traceback.format_exc()}")
            
            # Only rerun if assessment completed successfully
            if st.session_state.get('assessment_complete'):
                st.rerun()
        
        # Display results if assessment is complete
        if st.session_state.assessment_complete and st.session_state.report_content:
            st.markdown("---")
            
            # Threat summary
            self.display_threat_summary(st.session_state.all_data)
            
            st.markdown("---")
            
            # Report display
            st.header("📊 Threat Assessment Report")
            
            # Display report in expandable section with Mermaid support
            with st.expander("📋 View Full Report", expanded=True):
                # Professional report display with dynamic height
                mermaid_html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; frame-ancestors 'self';">
                    <style>
                        body {{
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            background-color: #ffffff;
                            color: #262730;
                            margin: 0;
                            padding: 20px;
                            line-height: 1.6;
                        }}
                        .report-container {{
                            width: calc(100vw - 40px);
                            margin: 0;
                            background: #ffffff;
                            padding: 15px;
                            box-sizing: border-box;
                        }}
                        h1 {{
                            color: #2c3e50;
                            border-bottom: 3px solid #667eea;
                            padding-bottom: 10px;
                            margin-bottom: 20px;
                        }}
                        h2 {{
                            color: #34495e;
                            margin-top: 30px;
                            border-left: 4px solid #667eea;
                            padding-left: 15px;
                        }}
                        h3 {{
                            color: #2c3e50;
                            margin-top: 25px;
                        }}
                        .critical {{
                            background-color: #fee;
                            color: #c53030;
                            padding: 2px 6px;
                            border-radius: 4px;
                            font-weight: bold;
                        }}
                        .mitre {{
                            background-color: #e6f3ff;
                            color: #1a365d;
                            padding: 2px 6px;
                            border-radius: 3px;
                            font-family: monospace;
                            font-weight: bold;
                        }}
                        .mermaid {{
                            text-align: center;
                            margin: 20px 0;
                            padding: 20px;
                            background-color: #f8f9fa;
                            border: 1px solid #dee2e6;
                            border-radius: 5px;
                        }}
                    </style>
                    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
                </head>
                <body>
                    <div class="report-container">
                        {st.session_state.report_content}
                    </div>
                    
                    <script>
                        mermaid.initialize({{
                            startOnLoad: true,
                            theme: 'default',
                            securityLevel: 'strict',
                            flowchart: {{
                                useMaxWidth: true,
                                htmlLabels: false
                            }},
                            themeVariables: {{
                                background: '#ffffff',
                                primaryColor: '#667eea',
                                primaryTextColor: '#262730',
                                fontFamily: 'Arial, sans-serif'
                            }}
                        }});
                        
                        function renderMermaid() {{
                            const mermaidElements = document.querySelectorAll('.mermaid');
                            mermaidElements.forEach((element, index) => {{
                                if (!element.getAttribute('data-processed')) {{
                                    try {{
                                        mermaid.render(`mermaid-${{index}}`, element.textContent, (svgCode) => {{
                                            element.innerHTML = svgCode;
                                            element.setAttribute('data-processed', 'true');
                                        }});
                                    }} catch (error) {{
                                        console.error('Mermaid render error:', error);
                                        element.innerHTML = '<p>Diagram rendering failed</p>';
                                    }}
                                }}
                            }});
                        }}
                        
                        function adjustHeight() {{
                            const body = document.body;
                            const html = document.documentElement;
                            const height = Math.max(
                                body.scrollHeight,
                                body.offsetHeight,
                                html.clientHeight,
                                html.scrollHeight,
                                html.offsetHeight
                            );
                            
                            window.parent.postMessage({{
                                type: 'streamlit:setFrameHeight',
                                height: height + 100
                            }}, '*');
                        }}
                        
                        document.addEventListener('DOMContentLoaded', function() {{
                            setTimeout(() => {{
                                renderMermaid();
                                setTimeout(adjustHeight, 1000);
                            }}, 500);
                        }});
                        
                        window.addEventListener('load', () => {{
                            setTimeout(() => {{
                                renderMermaid();
                                setTimeout(adjustHeight, 1000);
                            }}, 1000);
                        }});
                        
                        setInterval(adjustHeight, 3000);
                    </script>
                </body>
                </html>
                """
                
                # Calculate dynamic height
                content_length = len(st.session_state.report_content)
                word_count = len(st.session_state.report_content.split())
                diagram_count = st.session_state.report_content.count('mermaid')
                estimated_height = max(word_count * 2 + diagram_count * 400 + 500, 1000)
                
                st.components.v1.html(mermaid_html, height=estimated_height, scrolling=True)
            
            # Reset button
            if st.button("🔄 New Assessment"):
                # Reset all assessment-related session state
                keys_to_reset = [
                    'assessment_complete', 'assessment_running', 'report_content', 
                    'all_data', 'product_name', 'suggestions', 'selected_product', 
                    'last_search', 'product_search', 'last_request'
                ]
                
                for key in keys_to_reset:
                    if key in st.session_state:
                        del st.session_state[key]
                
                # Reset form state by clearing the text input
                st.session_state.product_search = ""
                
                st.rerun()

# Run the app
if __name__ == "__main__":
    app = ThreatModelingWebApp()
    app.main()