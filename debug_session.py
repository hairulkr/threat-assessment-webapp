#!/usr/bin/env python3
"""
Debug session persistence
"""
import streamlit as st
import time
import hashlib

st.set_page_config(page_title="Session Debug", page_icon="🔍")

st.title("🔍 Session Debug")

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'login_timestamp' not in st.session_state:
    st.session_state.login_timestamp = 0

def generate_session_hash(timestamp: float) -> str:
    data = f"{timestamp}:threat_modeling_2024"
    return hashlib.md5(data.encode()).hexdigest()[:16]

# Debug current state
st.subheader("Current State")
col1, col2 = st.columns(2)

with col1:
    st.write("**Session State:**")
    st.json({
        "authenticated": st.session_state.get('authenticated', False),
        "login_timestamp": st.session_state.get('login_timestamp', 0)
    })

with col2:
    st.write("**Query Params:**")
    try:
        query_params = dict(st.query_params)
        st.json(query_params)
    except Exception as e:
        st.error(f"Query params error: {e}")

# Try to restore session
st.subheader("Session Restoration Test")

if st.button("🔄 Try Restore Session"):
    try:
        query_params = st.query_params
        st.write(f"Raw query_params type: {type(query_params)}")
        st.write(f"Query params: {dict(query_params)}")
        
        if query_params.get('auth') == 'true':
            st.success("Found auth=true in query params")
            try:
                login_time = float(query_params.get('t', '0'))
                provided_hash = query_params.get('h', '')
                
                st.write(f"Login time: {login_time}")
                st.write(f"Provided hash: {provided_hash}")
                
                expected_hash = generate_session_hash(login_time)
                st.write(f"Expected hash: {expected_hash}")
                
                if provided_hash == expected_hash:
                    st.success("Hash validation passed!")
                    current_time = time.time()
                    if current_time - login_time < 7200:  # 2 hours
                        st.success("Session is still valid!")
                        st.session_state.authenticated = True
                        st.session_state.login_timestamp = login_time
                    else:
                        st.error("Session expired")
                else:
                    st.error("Hash validation failed")
            except Exception as e:
                st.error(f"Error parsing session data: {e}")
        else:
            st.warning("No auth parameter found")
    except Exception as e:
        st.error(f"Error accessing query params: {e}")

# Login test
st.subheader("Login Test")

if not st.session_state.get('authenticated', False):
    if st.button("🚀 Test Login"):
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
            st.success("Login successful! Query params set.")
            st.rerun()
        except Exception as e:
            st.error(f"Error setting query params: {e}")
else:
    st.success("✅ Logged in!")
    if st.button("🚪 Logout"):
        st.session_state.authenticated = False
        st.session_state.login_timestamp = 0
        try:
            st.query_params.clear()
            st.success("Logged out! Query params cleared.")
            st.rerun()
        except Exception as e:
            st.error(f"Error clearing query params: {e}")

# Manual URL test
st.subheader("Manual URL Test")
st.write("Try adding these parameters to your URL manually:")
current_time = time.time()
test_hash = generate_session_hash(current_time)
test_url = f"?auth=true&t={int(current_time)}&h={test_hash}"
st.code(test_url)