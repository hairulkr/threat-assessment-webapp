#!/usr/bin/env python3
"""
Quick launcher for the Streamlit web app
"""

import subprocess
import sys
import os

def main():
    """Launch the Streamlit app"""
    
    # Check if streamlit is installed
    try:
        import streamlit
    except ImportError:
        print("❌ Streamlit not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "streamlit"])
    
    # Check for .env file
    if not os.path.exists('.env'):
        print("⚠️  .env file not found. Please create one with your API keys:")
        print("GEMINI_API_KEY=your_key_here")
        print("SHODAN_API_KEY=your_key_here")
        print("GOOGLE_API_KEY=your_key_here")
        print("GOOGLE_CSE_ID=your_cse_id_here")
        return
    
    # Launch Streamlit app
    print("🚀 Launching Cybersecurity Threat Assessment Web App...")
    print("📱 App will open at: http://localhost:8501")
    subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py"])

if __name__ == "__main__":
    main()