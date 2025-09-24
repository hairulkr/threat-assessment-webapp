#!/usr/bin/env python3
"""
Session verification script - run this to test session management
"""
import streamlit as st
import time
import os

def main():
    st.set_page_config(page_title="Session Test", page_icon="🔐")
    
    st.title("🔐 Session Management Test")
    
    # Initialize session state
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
    
    def check_session_timeout():
        if not st.session_state.get('authenticated', False):
            return False
            
        current_time = time.time()
        last_activity = st.session_state.get('last_activity', 0)
        session_timeout = 7200  # 2 hours
        
        if current_time - last_activity > session_timeout:
            st.session_state.authenticated = False
            st.session_state.login_timestamp = 0
            st.session_state.last_activity = 0
            return False
            
        st.session_state.last_activity = current_time
        return True
    
    def get_session_time_remaining():
        if not st.session_state.get('authenticated', False):
            return 0
            
        current_time = time.time()
        last_activity = st.session_state.get('last_activity', 0)
        session_timeout = 7200  # 2 hours
        
        remaining = session_timeout - (current_time - last_activity)
        return max(0, int(remaining))
    
    def logout():
        st.session_state.authenticated = False
        st.session_state.login_timestamp = 0
        st.session_state.last_activity = 0
    
    # Check authentication
    if check_session_timeout():
        # User is authenticated and session is valid
        st.success("✅ Session Active")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Authentication Status", "Logged In")
            remaining = get_session_time_remaining()
            minutes = remaining // 60
            seconds = remaining % 60
            st.metric("Session Time", f"{minutes}m {seconds}s")
        
        with col2:
            st.metric("Login Timestamp", 
                     time.strftime("%H:%M:%S", time.localtime(st.session_state.login_timestamp)))
            st.metric("Last Activity", 
                     time.strftime("%H:%M:%S", time.localtime(st.session_state.last_activity)))
        
        if st.button("🚪 Logout"):
            logout()
            st.rerun()
        
        # Auto-refresh every 5 seconds to show countdown
        if st.button("🔄 Refresh Session"):
            st.rerun()
        
        # Test session timeout
        st.subheader("🧪 Test Session Timeout")
        if st.button("⏰ Simulate Timeout (Set activity to 3 hours ago)"):
            st.session_state.last_activity = time.time() - 10800  # 3 hours ago
            st.rerun()
        
    else:
        # User needs to authenticate
        st.warning("🔒 Authentication Required")
        
        # Check if locked out
        current_time = time.time()
        if st.session_state.login_lockout_time > current_time:
            remaining_time = int(st.session_state.login_lockout_time - current_time)
            st.error(f"🔒 Too many failed attempts. Try again in {remaining_time} seconds.")
            return
        
        with st.form("login_form"):
            password = st.text_input("Enter password:", type="password")
            
            # Show remaining attempts
            remaining_attempts = max(0, 5 - st.session_state.login_attempts)
            if st.session_state.login_attempts > 0:
                st.warning(f"⚠️ {remaining_attempts} attempts remaining")
            
            if st.form_submit_button("🚀 Login"):
                # Get password from environment or use default
                try:
                    app_password = st.secrets["APP_PASSWORD"]
                except:
                    app_password = os.getenv('APP_PASSWORD', 'test123')
                
                if password == app_password:
                    current_time = time.time()
                    st.session_state.authenticated = True
                    st.session_state.login_attempts = 0
                    st.session_state.login_timestamp = current_time
                    st.session_state.last_activity = current_time
                    st.success("✅ Login successful!")
                    st.rerun()
                else:
                    st.session_state.login_attempts += 1
                    
                    if st.session_state.login_attempts >= 5:
                        st.session_state.login_lockout_time = current_time + 300  # 5 minutes
                        st.error("🔒 Too many failed attempts. Locked out for 5 minutes.")
                    else:
                        remaining = 5 - st.session_state.login_attempts
                        st.error(f"❌ Invalid password. {remaining} attempts remaining.")
    
    # Debug information
    with st.expander("🔍 Debug Information"):
        st.json({
            "authenticated": st.session_state.get('authenticated', False),
            "login_attempts": st.session_state.get('login_attempts', 0),
            "login_timestamp": st.session_state.get('login_timestamp', 0),
            "last_activity": st.session_state.get('last_activity', 0),
            "current_time": time.time(),
            "session_valid": check_session_timeout()
        })

if __name__ == "__main__":
    main()