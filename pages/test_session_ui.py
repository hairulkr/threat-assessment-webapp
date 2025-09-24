#!/usr/bin/env python3
"""
UI-based session test
"""
import streamlit as st
import time
import hashlib

st.set_page_config(page_title="Session Test", page_icon="🧪")

st.title("🧪 Session Persistence Test")

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'login_timestamp' not in st.session_state:
    st.session_state.login_timestamp = 0

def generate_session_hash(timestamp: float) -> str:
    data = f"{timestamp}:threat_modeling_2024"
    return hashlib.md5(data.encode()).hexdigest()[:16]

# Show current URL
st.subheader("Current URL Info")
try:
    query_params = dict(st.query_params)
    st.write(f"**Query Parameters:** {query_params}")
    st.write(f"**Current URL:** {st.get_option('browser.serverAddress') or 'localhost'}:{st.get_option('server.port')}")
except Exception as e:
    st.error(f"Error getting URL info: {e}")

# Show session state
st.subheader("Session State")
col1, col2 = st.columns(2)
with col1:
    st.metric("Authenticated", st.session_state.authenticated)
with col2:
    if st.session_state.login_timestamp:
        login_time_str = time.strftime("%H:%M:%S", time.localtime(st.session_state.login_timestamp))
        st.metric("Login Time", login_time_str)
    else:
        st.metric("Login Time", "Not logged in")

# Test login
st.subheader("Test Session")

if not st.session_state.authenticated:
    if st.button("🚀 Test Login", type="primary"):
        current_time = time.time()
        st.session_state.authenticated = True
        st.session_state.login_timestamp = current_time
        
        # Set query params
        session_hash = generate_session_hash(current_time)
        try:
            st.query_params.update({
                "auth": "true",
                "t": str(int(current_time)),
                "h": session_hash
            })
            st.success("✅ Login successful! Check URL for parameters.")
            st.info("Now refresh the page (F5) to test session persistence.")
            st.rerun()
        except Exception as e:
            st.error(f"❌ Error setting query params: {e}")
else:
    st.success("✅ Currently logged in!")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Refresh Test"):
            st.rerun()
    
    with col2:
        if st.button("🚪 Logout"):
            st.session_state.authenticated = False
            st.session_state.login_timestamp = 0
            try:
                st.query_params.clear()
                st.success("Logged out!")
                st.rerun()
            except Exception as e:
                st.error(f"Error clearing params: {e}")

# Session restoration test
st.subheader("Session Restoration Test")

if st.button("🔍 Test Session Restoration"):
    try:
        query_params = st.query_params
        
        if query_params.get('auth') == 'true':
            st.success("✅ Found auth=true in URL")
            
            login_time = float(query_params.get('t', '0'))
            provided_hash = query_params.get('h', '')
            expected_hash = generate_session_hash(login_time)
            
            st.write(f"**Login Time:** {login_time}")
            st.write(f"**Provided Hash:** {provided_hash}")
            st.write(f"**Expected Hash:** {expected_hash}")
            
            if provided_hash == expected_hash:
                st.success("✅ Hash validation passed")
                
                current_time = time.time()
                age = current_time - login_time
                st.write(f"**Session Age:** {age:.0f} seconds")
                
                if age < 7200:  # 2 hours
                    st.success("✅ Session is still valid")
                    if not st.session_state.authenticated:
                        st.session_state.authenticated = True
                        st.session_state.login_timestamp = login_time
                        st.info("Session restored from URL!")
                        st.rerun()
                else:
                    st.error("❌ Session expired (> 2 hours)")
            else:
                st.error("❌ Hash validation failed")
        else:
            st.warning("⚠️ No auth parameter in URL")
            
    except Exception as e:
        st.error(f"❌ Error during restoration test: {e}")

# Instructions
st.subheader("📋 Test Instructions")
st.markdown("""
1. **Click "Test Login"** - This sets session parameters in URL
2. **Refresh the page (F5)** - This simulates a page reload
3. **Click "Test Session Restoration"** - This checks if session can be restored
4. **Check the URL** - You should see `?auth=true&t=...&h=...` parameters

**Expected behavior:** After refresh, session should be automatically restored.
""")

# Manual URL test
with st.expander("🔧 Manual URL Test"):
    st.write("Copy this URL and paste it in a new tab:")
    current_time = time.time()
    test_hash = generate_session_hash(current_time)
    base_url = "your-streamlit-url"  # Replace with actual URL
    test_url = f"{base_url}?auth=true&t={int(current_time)}&h={test_hash}"
    st.code(test_url)