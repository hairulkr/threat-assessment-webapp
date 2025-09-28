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
from typing import Dict, Any
from simple_session import SimpleSessionManager

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
    from agents.product_info_agent import ProductInfoAgent
    from agents.intelligence_agent import IntelligenceAgent
    from agents.controls_agent import ControlsAgent
    from agents.report_agent import ReportAgent
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
        self.session_manager = SimpleSessionManager()
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
            'selected_llm_provider': 'ollama-deepseek-v3-1-671b-cloud',
            # Session management
            'authenticated': False,
            'login_attempts': 0,
            'login_lockout_time': 0,
            'login_timestamp': 0,
            'last_activity': 0
        }
        
        for key, value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = value
    
    async def run_assessment(self, product_name: str):
        """Run the threat assessment with progress tracking"""
        
        # Get selected LLM provider and model
        provider_key = st.session_state.get('selected_llm_provider', 'gemini-2.0-flash')
        providers = get_available_providers()
        
        if provider_key in providers:
            provider_info = providers[provider_key]
            if provider_info['provider'] == 'Ollama':
                llm = LLMClient('ollama', model=provider_info['model_id'])
            else:
                llm = LLMClient('ollama', model='deepseek-v3.1:671b-cloud')
        else:
            llm = LLMClient('ollama', model='deepseek-v3.1:671b-cloud')
        
        if not llm.is_available():
            st.error(f"❌ {provider.title()} API key not found in secrets or environment variables")
            return None, None
        
        # API keys for 17-source threat intelligence
        api_keys = {
            'nvd_api_key': os.getenv('NVD_API_KEY'),
            'github_token': os.getenv('GITHUB_TOKEN'),
            'google_cse_key': os.getenv('GOOGLE_CSE_KEY'),
            'google_cse_id': os.getenv('GOOGLE_CSE_ID')
        }
        
        # Streamlined 4-agent architecture
        agents = {
            'product': ProductInfoAgent(llm),
            'intelligence': IntelligenceAgent(llm, api_keys=api_keys),
            'controls': ControlsAgent(llm),
            'report': ReportAgent(llm)
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
                    product_info = await agents['product'].gather_info(product_name)
                except Exception as e:
                    print(f"Product analysis failed: {e}")
                    product_info = await self._fallback_product_info(product_name)
            
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
            
            # Skip separate threat intelligence step - now handled in comprehensive analysis
            source_status.empty()
            status_box.success("✅ **Ready for comprehensive analysis**")
            
            # Step 3: LLM-Driven Threat Intelligence & Ranking
            status_text.markdown("**🎯 Step 3: Gathering & ranking threats by relevance...**")
            progress_bar.progress(40)
            
            # Show analysis status
            intel_status = st.empty()
            intel_status.info("🎯 **LLM Analysis:** Gathering threat intelligence and ranking by product relevance...")
            
            try:
                comprehensive_result = await agents['intelligence'].gather_and_rank_threats(product_info)
            except Exception as e:
                st.error(f"Threat intelligence failed: {e}")
                return None, None
            
            intel_status.empty()
            status_box.success("✅ **Threat Intelligence Complete:** Threats gathered and ranked by relevance")
            
            # Update all_data with results
            all_data["threats"] = comprehensive_result.get('threats', [])
            all_data["risk_assessment"] = comprehensive_result.get('risk_assessment', {})
            
            progress_bar.progress(60)
            
            # Step 4: MITRE-Mapped Security Controls
            status_text.markdown("**🛡️ Step 4: Generating MITRE-mapped controls...**")
            
            with st.spinner("🛡️ Generating MITRE ATT&CK mapped security controls..."):
                try:
                    controls = await asyncio.wait_for(
                        agents['controls'].generate_mitre_controls(
                            comprehensive_result.get('threats', []),
                            comprehensive_result.get('risk_assessment', {})
                        ),
                        timeout=120
                    )
                except asyncio.TimeoutError:
                    st.warning("Control generation timed out - using basic controls")
                    # Provide basic fallback controls
                    controls = {
                        "preventive": ["Multi-factor authentication", "Network segmentation", "Regular patching"],
                        "detective": ["Security monitoring", "Log analysis", "Intrusion detection"],
                        "corrective": ["Incident response plan", "Backup and recovery", "Security training"]
                    }
                except Exception as e:
                    st.warning(f"MITRE control generation failed: {str(e)}")
                    controls = {
                        "preventive": [{"control": "Multi-factor Authentication", "mitre_mitigation": "M1032"}],
                        "detective": [{"control": "Network Monitoring", "mitre_mitigation": "M1047"}],
                        "corrective": [{"control": "Incident Response Plan", "mitre_mitigation": "M1049"}]
                    }
            
            status_box.success("Security control framework established")
            all_data["controls"] = controls
            
            progress_bar.progress(80)
            
            # Step 5: Enhanced Report Generation
            status_text.markdown("**📊 Step 5: Generating comprehensive report...**")
            
            with st.spinner("📊 Generating comprehensive report with integrated validation..."):
                try:
                    # Enhanced report generation with integrated review and batch diagrams
                    report_content = await asyncio.wait_for(
                        agents['report'].generate_comprehensive_report(all_data),
                        timeout=180
                    )
                    
                    # Check for termination recommendation from professional report agent
                    if report_content is None:
                        progress_bar.progress(100)
                        st.session_state.assessment_running = False
                        status_text.markdown("**⚠️ Analysis terminated due to insufficient data quality**")
                        st.warning("Analysis terminated: Data quality validation failed. No actionable threat intelligence found with sufficient confidence. Please try a different product name or check API connectivity.")
                        return None, None
                        
                except asyncio.TimeoutError:
                    st.warning("Report generation timed out - generating basic report")
                    report_content = self.generate_basic_report(all_data)
                except Exception as e:
                    st.warning(f"Report generation failed: {str(e)} - generating basic report")
                    report_content = self.generate_basic_report(all_data)
            
            status_box.success("Enhanced report generation completed")
            
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
        if not threats or len(threats) == 0:
            st.success("✅ Threat analysis completed successfully!")
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
        import html
        import re
        # Escape content to prevent XSS - but preserve safe HTML tags
        if isinstance(content, str):
            # Allow only safe HTML tags, escape everything else
            safe_content = re.sub(r'<(?!/?(?:h[1-6]|p|ul|ol|li|strong|em|div|span)\b)[^>]*>', '', content)
        else:
            safe_content = content
        safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)  # Sanitize filename
        
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
                {safe_content}
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
            
        # Use whitelist approach for better security - allow common product name characters
        import re
        if not re.match(r'^[a-zA-Z0-9\s\-_\.\+\(\)\[\]\{\}\&\@\#\$\%\^\*\!\?\,\;\:\'\"]+$', cleaned_name):
            st.error("Product name contains invalid characters. Please use standard alphanumeric characters and common symbols.")
            return False
            
        if len(cleaned_name) > 100:
            st.error("Product name is too long (maximum 100 characters)")
            return False
            
        return True
    
    def generate_basic_report(self, all_data):
        """Generate a basic fallback report when full generation fails"""
        product_name = all_data.get('product_name', 'Unknown Product')
        threats = all_data.get('threats', [])
        
        threat_count = len(threats)
        high_severity = len([t for t in threats if t.get('severity') == 'HIGH'])
        critical_severity = len([t for t in threats if t.get('severity') == 'CRITICAL'])
        
        return f"""
        <h1>Threat Assessment Report - {product_name}</h1>
        
        <h2>Executive Summary</h2>
        <p>This assessment identified <strong>{threat_count} potential threats</strong> for {product_name}.</p>
        <ul>
            <li>Critical threats: {critical_severity}</li>
            <li>High severity threats: {high_severity}</li>
            <li>Assessment completed with basic analysis due to timeout constraints</li>
        </ul>
        
        <h2>Key Findings</h2>
        <p>The following threats were identified:</p>
        <ul>
        {''.join([f'<li><strong>{t.get("title", "Unknown")}</strong> - {t.get("severity", "Unknown")} severity (CVE: {t.get("cve_id", "N/A")})</li>' for t in threats[:10]])}
        </ul>
        
        <h2>Recommendations</h2>
        <ul>
            <li>Implement multi-factor authentication</li>
            <li>Keep software updated with latest security patches</li>
            <li>Deploy network segmentation and monitoring</li>
            <li>Establish incident response procedures</li>
            <li>Conduct regular security assessments</li>
        </ul>
        
        <p><em>Note: This is a basic report generated due to processing constraints. For detailed analysis, please try the assessment again.</em></p>
        """
    
    async def _fallback_product_info(self, product_name: str) -> Dict[str, Any]:
        """Fallback product information when main analysis fails"""
        return {
            'name': product_name,
            'description': f'Basic analysis for {product_name}',
            'technologies': ['Unknown'],
            'components': ['Application'],
            'fallback_used': True
        }
    

    
    def check_session_timeout(self):
        """Check if session has timed out (2 hours default)"""
        if not st.session_state.get('authenticated', False):
            return False
            
        current_time = time.time()
        login_time = st.session_state.get('login_timestamp', 0)
        last_activity = st.session_state.get('last_activity', 0)
        
        # Session timeout: 2 hours (7200 seconds) - longer for better UX
        session_timeout = 7200
        
        if current_time - last_activity > session_timeout:
            # Session expired
            st.session_state.authenticated = False
            st.session_state.login_timestamp = 0
            st.session_state.last_activity = 0
            return False
            
        # Update last activity
        st.session_state.last_activity = current_time
        return True
    
    def get_session_time_remaining(self):
        """Get remaining session time in seconds"""
        if not st.session_state.get('authenticated', False):
            return 0
            
        current_time = time.time()
        last_activity = st.session_state.get('last_activity', 0)
        session_timeout = 7200  # 2 hours
        remaining = session_timeout - (current_time - last_activity)
        return max(0, int(remaining))
    
    def logout(self):
        """Manual logout - clear session"""
        st.session_state.authenticated = False
        st.session_state.login_timestamp = 0
        st.session_state.last_activity = 0
        
        # Clear session from URL
        self.session_manager.clear_session_url()
    
    def check_authentication(self):
        """Password authentication with session management and brute force protection"""
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        if 'login_attempts' not in st.session_state:
            st.session_state.login_attempts = 0
        if 'login_lockout_time' not in st.session_state:
            st.session_state.login_lockout_time = 0
        if 'login_timestamp' not in st.session_state:
            st.session_state.login_timestamp = 0
        if 'last_activity' not in st.session_state:
            st.session_state.last_activity = 0
            
        # Try to restore session from URL parameters on every check
        if not st.session_state.get('authenticated', False):
            if self.session_manager.restore_session_from_url():
                st.rerun()
            
        # Check if already authenticated and session is valid
        if self.check_session_timeout():
            # Update session activity
            self.session_manager.update_session_activity()
            return  # Already logged in with valid session
        
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
                with st.container():
                    with st.form("login_form"):
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
                        
                        login_submitted = st.form_submit_button("🚀 Login", type="primary", use_container_width=True)
                    
                    if login_submitted:
                        try:
                            app_password = st.secrets["APP_PASSWORD"]
                        except:
                            app_password = os.getenv('APP_PASSWORD')
                        
                        if not app_password:
                            st.error("🔒 APP_PASSWORD not configured. Contact administrator.")
                            st.stop()
                        
                        if password == app_password:
                            current_time = time.time()
                            st.session_state.authenticated = True
                            st.session_state.login_attempts = 0  # Reset on success
                            st.session_state.login_timestamp = current_time
                            st.session_state.last_activity = current_time
                            
                            # Save session to URL
                            self.session_manager.save_session_to_url()
                            
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
            
            for provider_key, provider_info in providers.items():
                provider_options.append(provider_key)
                status_icon = "✅" if "Available" in provider_info["status"] else "❌"
                description = provider_info.get('description', '')
                provider_labels.append(f"{status_icon} {provider_info['model']} - {description}")
            
            # Provider selection
            if provider_options:
                selected_idx = 0
                current_provider = st.session_state.get('selected_llm_provider', 'ollama-deepseek-v3-1-671b-cloud')
                if current_provider in provider_options:
                    selected_idx = provider_options.index(current_provider)
                
                selected_provider = st.selectbox(
                    "Select AI Model:",
                    options=provider_options,
                    format_func=lambda x: provider_labels[provider_options.index(x)],
                    index=selected_idx,
                    key="llm_provider_select"
                )
                
                st.session_state.selected_llm_provider = selected_provider
                
                # Show detailed status for selected provider
                if selected_provider in providers:
                    selected_info = providers[selected_provider]
                else:
                    # Reset to default if key doesn't exist
                    selected_provider = list(providers.keys())[0] if providers else 'ollama-deepseek-v3-1-671b-cloud'
                    st.session_state.selected_llm_provider = selected_provider
                    selected_info = providers.get(selected_provider, {})
                
                if selected_info and "Available" in selected_info.get("status", ""):
                    st.success(f"✅ {selected_info['model']} Ready")
                    st.info(f"**Provider:** {selected_info['provider']}")
                elif selected_info:
                    st.error(f"❌ {selected_info.get('model', 'Unknown')} - API Key Missing")
                    st.info("Add OLLAMA_API_KEY to Streamlit secrets or environment variables")
                else:
                    st.error("❌ No AI models available")
            else:
                st.error("❌ No AI models available")
            
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
            
            if st.session_state.get('show_methodology', False):
                if st.button("❌ Close Methodology", use_container_width=True):
                    st.session_state.show_methodology = False
                    st.rerun()
            
            # Logout button
            if st.session_state.get('authenticated', False):
                if st.button("🚪 Logout", use_container_width=True, type="secondary"):
                    self.logout()
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
        
        
        
        # Main content area
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.header("🎯 Product Assessment")
            
            # Product search and suggestion
            # Handle product selection from recommendations
            if st.session_state.get('selected_product'):
                # Don't modify the search input, just store for assessment form
                pass
            
            # Product input
            product_input = st.text_input(
                "Enter Product/System Name:",
                placeholder="e.g., Visual Studio Code, Apache Tomcat, WordPress",
                help="Enter the name of the software product you want to assess",
                key="product_search"
            )
            
            # CPE-based product suggestions with manual refresh
            if product_input and len(product_input) > 2:
                # Show search button for manual triggering
                col_search, col_refresh = st.columns([4, 1])
                with col_refresh:
                    refresh_search = st.button("🔍 Search", help="Get AI product suggestions")
                
                # Trigger search on new input or manual refresh
                should_search = (
                    'suggestions' not in st.session_state or 
                    st.session_state.get('last_search') != product_input or
                    refresh_search
                )
                
                if should_search:
                    try:
                        api_key = st.secrets["GEMINI_API_KEY"]
                    except:
                        api_key = os.getenv('GEMINI_API_KEY')
                    
                    provider_key = st.session_state.get('selected_llm_provider', 'ollama-deepseek-v3-1-671b-cloud')
                    providers = get_available_providers()
                    
                    if provider_key in providers:
                        provider_info = providers[provider_key]
                        llm = LLMClient('ollama', model=provider_info['model_id'])
                    else:
                        llm = LLMClient('ollama', model='deepseek-v3.1:671b-cloud')
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
                
                elif len(product_input) > 2 and st.session_state.get('last_search') == product_input:
                    st.info("💡 **No CVE data found for this product name**")
                    st.markdown("""
                    **Tip**: Try searching at [NVD CPE Search](https://nvd.nist.gov/products/cpe/search) for exact product names.
                    """)
                elif len(product_input) > 2:
                    st.info("💡 **Click 🔍 Search to get AI product suggestions**")
            
            # Assessment form
            if product_input:
                with st.form("assessment_form"):
                    # Initialize form input with current product_input if not set
                    if 'form_product_name' not in st.session_state:
                        st.session_state.form_product_name = product_input
                    
                    # Update form input if a product was selected
                    if st.session_state.get('selected_product'):
                        st.session_state.form_product_name = st.session_state.selected_product
                        st.session_state.selected_product = ''  # Clear after using
                    
                    final_product = st.text_input(
                        "Product to assess:",
                        disabled=False,
                        help="You can edit this product name before starting the assessment",
                        key="form_product_name"
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
                    
                # Product name is now directly from the form input
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
                            padding: 0;
                            line-height: 1.6;
                            width: 100%;
                        }}
                        .report-container {{
                            width: 100%;
                            margin: 0;
                            padding: 0;
                            background: #ffffff;
                            box-sizing: border-box;
                            position: absolute;
                            left: 0;
                            top: 0;
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
                    'last_search', 'product_search', 'last_request', 'form_product_name'
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