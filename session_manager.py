"""
Session persistence manager using browser localStorage
"""
import streamlit as st
import streamlit.components.v1 as components
import time
import json
import hashlib

class SessionManager:
    """Manages persistent sessions across page refreshes using localStorage"""
    
    def __init__(self):
        self.session_timeout = 7200  # 2 hours
    
    def generate_session_token(self, timestamp: float) -> str:
        """Generate a secure session token"""
        # Simple token based on timestamp and a secret
        secret = "threat_modeling_session_2024"
        token_data = f"{timestamp}:{secret}"
        return hashlib.sha256(token_data.encode()).hexdigest()[:32]
    
    def save_session_to_browser(self, authenticated: bool, login_timestamp: float, last_activity: float):
        """Save session data to browser localStorage"""
        if authenticated:
            session_token = self.generate_session_token(login_timestamp)
            session_data = {
                'authenticated': True,
                'login_timestamp': login_timestamp,
                'last_activity': last_activity,
                'session_token': session_token
            }
        else:
            session_data = {'authenticated': False}
        
        # JavaScript to save to localStorage
        js_code = f"""
        <script>
            localStorage.setItem('threat_modeling_session', JSON.stringify({json.dumps(session_data)}));
        </script>
        """
        components.html(js_code, height=0)
    
    def load_session_from_browser(self):
        """Load session data from browser localStorage"""
        # JavaScript to retrieve from localStorage
        js_code = """
        <script>
            const sessionData = localStorage.getItem('threat_modeling_session');
            if (sessionData) {
                const data = JSON.parse(sessionData);
                window.parent.postMessage({
                    type: 'session_data',
                    data: data
                }, '*');
            } else {
                window.parent.postMessage({
                    type: 'session_data',
                    data: null
                }, '*');
            }
        </script>
        """
        
        # Use a placeholder to capture the response
        session_placeholder = st.empty()
        with session_placeholder.container():
            components.html(js_code, height=0)
        
        # Check if we have session data in query params (fallback method)
        query_params = st.experimental_get_query_params()
        if 'session_restored' in query_params:
            return self._parse_session_from_params(query_params)
        
        return None
    
    def _parse_session_from_params(self, query_params):
        """Parse session data from URL parameters (fallback method)"""
        try:
            if 'auth' in query_params and query_params['auth'][0] == 'true':
                login_time = float(query_params.get('login_time', [0])[0])
                last_activity = float(query_params.get('last_activity', [0])[0])
                session_token = query_params.get('token', [''])[0]
                
                # Validate token
                expected_token = self.generate_session_token(login_time)
                if session_token == expected_token:
                    return {
                        'authenticated': True,
                        'login_timestamp': login_time,
                        'last_activity': last_activity,
                        'session_token': session_token
                    }
        except (ValueError, IndexError, KeyError):
            pass
        
        return None
    
    def is_session_valid(self, session_data):
        """Check if session data is valid and not expired"""
        if not session_data or not session_data.get('authenticated'):
            return False
        
        current_time = time.time()
        last_activity = session_data.get('last_activity', 0)
        login_timestamp = session_data.get('login_timestamp', 0)
        
        # Check session timeout
        if current_time - last_activity > self.session_timeout:
            return False
        
        # Validate session token
        expected_token = self.generate_session_token(login_timestamp)
        if session_data.get('session_token') != expected_token:
            return False
        
        return True
    
    def restore_session_state(self, session_data):
        """Restore Streamlit session state from browser session data"""
        if session_data and self.is_session_valid(session_data):
            st.session_state.authenticated = True
            st.session_state.login_timestamp = session_data['login_timestamp']
            st.session_state.last_activity = time.time()  # Update activity
            st.session_state.login_attempts = 0
            return True
        else:
            # Clear invalid session
            self.clear_session()
            return False
    
    def clear_session(self):
        """Clear session from both Streamlit and browser"""
        # Clear Streamlit session
        st.session_state.authenticated = False
        st.session_state.login_timestamp = 0
        st.session_state.last_activity = 0
        
        # Clear browser localStorage
        js_code = """
        <script>
            localStorage.removeItem('threat_modeling_session');
        </script>
        """
        components.html(js_code, height=0)
    
    def update_activity(self):
        """Update last activity timestamp"""
        if st.session_state.get('authenticated', False):
            current_time = time.time()
            st.session_state.last_activity = current_time
            
            # Update browser storage
            self.save_session_to_browser(
                True,
                st.session_state.login_timestamp,
                current_time
            )