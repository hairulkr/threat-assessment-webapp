#!/usr/bin/env python3
"""
Simple test script to verify session management functionality
"""
import time
import os

class SessionTester:
    def __init__(self):
        self.session_data = {}
    
    def simulate_login(self, password):
        """Simulate login process"""
        correct_password = os.getenv('APP_PASSWORD', 'test123')
        
        if password == correct_password:
            current_time = time.time()
            self.session_data = {
                'authenticated': True,
                'login_timestamp': current_time,
                'last_activity': current_time,
                'login_attempts': 0
            }
            return True
        else:
            self.session_data['login_attempts'] = self.session_data.get('login_attempts', 0) + 1
            return False
    
    def check_session_timeout(self):
        """Check if session has timed out"""
        if not self.session_data.get('authenticated', False):
            return False
            
        current_time = time.time()
        last_activity = self.session_data.get('last_activity', 0)
        session_timeout = 7200  # 2 hours
        
        if current_time - last_activity > session_timeout:
            # Session expired
            self.session_data['authenticated'] = False
            self.session_data['login_timestamp'] = 0
            self.session_data['last_activity'] = 0
            return False
            
        # Update last activity
        self.session_data['last_activity'] = current_time
        return True
    
    def get_session_time_remaining(self):
        """Get remaining session time in seconds"""
        if not self.session_data.get('authenticated', False):
            return 0
            
        current_time = time.time()
        last_activity = self.session_data.get('last_activity', 0)
        session_timeout = 7200  # 2 hours
        
        remaining = session_timeout - (current_time - last_activity)
        return max(0, int(remaining))
    
    def logout(self):
        """Manual logout"""
        self.session_data = {
            'authenticated': False,
            'login_timestamp': 0,
            'last_activity': 0,
            'login_attempts': 0
        }

def test_session_functionality():
    """Test session management"""
    print("Testing Session Management Functionality")
    print("=" * 50)
    
    tester = SessionTester()
    
    # Test 1: Initial state
    print("Test 1: Initial state")
    print(f"Authenticated: {tester.session_data.get('authenticated', False)}")
    print(f"Session valid: {tester.check_session_timeout()}")
    print()
    
    # Test 2: Failed login
    print("Test 2: Failed login")
    result = tester.simulate_login("wrong_password")
    print(f"Login result: {result}")
    print(f"Login attempts: {tester.session_data.get('login_attempts', 0)}")
    print()
    
    # Test 3: Successful login
    print("Test 3: Successful login")
    result = tester.simulate_login("test123")  # Default test password
    print(f"Login result: {result}")
    print(f"Authenticated: {tester.session_data.get('authenticated', False)}")
    print(f"Session valid: {tester.check_session_timeout()}")
    
    remaining = tester.get_session_time_remaining()
    minutes = remaining // 60
    seconds = remaining % 60
    print(f"Time remaining: {minutes}m {seconds}s")
    print()
    
    # Test 4: Session activity update
    print("Test 4: Session activity update")
    time.sleep(2)  # Wait 2 seconds
    print(f"Session valid after activity: {tester.check_session_timeout()}")
    
    remaining = tester.get_session_time_remaining()
    minutes = remaining // 60
    seconds = remaining % 60
    print(f"Time remaining after activity: {minutes}m {seconds}s")
    print()
    
    # Test 5: Manual logout
    print("Test 5: Manual logout")
    tester.logout()
    print(f"Authenticated after logout: {tester.session_data.get('authenticated', False)}")
    print(f"Session valid after logout: {tester.check_session_timeout()}")
    print()
    
    # Test 6: Timeout simulation (shortened for testing)
    print("Test 6: Timeout simulation")
    tester.simulate_login("test123")
    print(f"Logged in: {tester.session_data.get('authenticated', False)}")
    
    # Simulate old activity (more than 2 hours ago)
    tester.session_data['last_activity'] = time.time() - 7300  # 2 hours and 5 minutes ago
    print(f"Session valid after timeout: {tester.check_session_timeout()}")
    print(f"Authenticated after timeout: {tester.session_data.get('authenticated', False)}")
    
    print("=" * 50)
    print("✅ Session functionality test completed!")

if __name__ == "__main__":
    test_session_functionality()