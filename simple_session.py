"""
Simple session persistence using URL parameters and Streamlit query params
"""
import streamlit as st
import time
import hashlib
import urllib.parse

class SimpleSessionManager:
    """Simple session manager using URL parameters for persistence"""
    
    def __init__(self):
        self.session_timeout = 7200  # 2 hours
        self.secret_key = "threat_modeling_2024"
    
    def generate_session_hash(self, timestamp: float) -> str:
        """Generate session hash for validation"""
        data = f"{timestamp}:{self.secret_key}"
        return hashlib.md5(data.encode()).hexdigest()[:16]
    
    def save_session_to_url(self):
        """Save session data to URL parameters"""
        if st.session_state.get('authenticated', False):
            login_time = st.session_state.get('login_timestamp', 0)
            session_hash = self.generate_session_hash(login_time)
            
            # Update query parameters
            st.query_params.update({
                "auth": "true",
                "t": str(int(login_time)),
                "h": session_hash
            })
    
    def restore_session_from_url(self):
        """Restore session from URL parameters"""
        query_params = st.query_params
        
        if query_params.get('auth') == 'true':
            try:
                login_time = float(query_params.get('t', '0'))
                provided_hash = query_params.get('h', '')
                
                # Validate hash
                expected_hash = self.generate_session_hash(login_time)
                if provided_hash == expected_hash:
                    # Check if session is still valid
                    current_time = time.time()
                    if current_time - login_time < self.session_timeout:
                        # Restore session
                        st.session_state.authenticated = True
                        st.session_state.login_timestamp = login_time
                        st.session_state.last_activity = current_time
                        st.session_state.login_attempts = 0
                        return True
                    else:
                        # Session expired, clear URL
                        self.clear_session_url()
                else:
                    # Invalid hash, clear URL
                    self.clear_session_url()
            except (ValueError, IndexError):
                self.clear_session_url()
        
        return False
    
    def clear_session_url(self):
        """Clear session from URL parameters"""
        st.query_params.clear()
    
    def update_session_activity(self):
        """Update session activity"""
        if st.session_state.get('authenticated', False):
            st.session_state.last_activity = time.time()
            # Optionally update URL timestamp
            self.save_session_to_url()