import requests
import sys

BASE_URL = "http://localhost:8000/api/v1/auth"

def test_auth():
    print("Testing Auth Endpoints...")
    
    # 1. Register
    print("Testing Registration...")
    username = "testuser_" + str(int(time.time()))
    email = f"{username}@example.com"
    password = "password123"
    
    payload = {
        "username": username,
        "email": email,
        "password": password,
        "full_name": "Test User"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/register", data=payload)
        if response.status_code == 200:
            print("SUCCESS: Registration successful")
            print(response.json())
        else:
            print(f"FAILURE: Registration failed with {response.status_code}")
            print(response.text)
            # If registration fails, we can't test login properly with this user
            return
            
    except Exception as e:
        print(f"ERROR: Registration request failed: {e}")
        return

    # 2. Login
    print("\nTesting Login...")
    login_payload = {
        "username": username,
        "password": password
    }
    
    try:
        response = requests.post(f"{BASE_URL}/token", data=login_payload)
        if response.status_code == 200:
            print("SUCCESS: Login successful")
            print(response.json())
        else:
            print(f"FAILURE: Login failed with {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"ERROR: Login request failed: {e}")

if __name__ == "__main__":
    import time
    test_auth()
