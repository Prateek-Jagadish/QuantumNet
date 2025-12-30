import requests
import sys
import os

BASE_URL = "http://localhost:8000/api/v1"

def test_file_share():
    print("Testing File Share Endpoints...")
    
    # 1. Register User A
    username_a = "user_a_" + str(int(os.urandom(4).hex(), 16))
    token_a, id_a = register_and_login(username_a)
    print(f"User A: {username_a} ({id_a})")
    
    # 2. Register User B
    username_b = "user_b_" + str(int(os.urandom(4).hex(), 16))
    token_b, id_b = register_and_login(username_b)
    print(f"User B: {username_b} ({id_b})")
    
    # 3. User A uploads file to User B
    print("\nUploading file...")
    file_content = b"This is a secret quantum file content."
    files = {'file': ('secret.txt', file_content, 'text/plain')}
    
    headers = {"Authorization": f"Bearer {token_a}"}
    try:
        response = requests.post(
            f"{BASE_URL}/chat/upload?recipient_id={id_b}",
            headers=headers,
            files=files
        )
        if response.status_code == 200:
            print("SUCCESS: File uploaded")
            print(response.json())
        else:
            print(f"FAILURE: Upload failed {response.status_code}")
            print(response.text)
            return
    except Exception as e:
        print(f"ERROR: Upload request failed: {e}")
        return

    # 4. Get Message History (as User B) to find the download link
    print("\nFetching history as User B...")
    headers_b = {"Authorization": f"Bearer {token_b}"}
    try:
        response = requests.get(f"{BASE_URL}/chat/history/{id_a}", headers=headers_b)
        messages = response.json()
        if not messages:
            print("FAILURE: No messages found")
            return
            
        last_msg = messages[-1]
        print(f"Last Message Content: {last_msg['content']}")
        
        import json
        content_json = json.loads(last_msg['content'])
        download_url = content_json.get('download_url')
        print(f"Download URL: {download_url}")
        
        if not download_url:
            print("FAILURE: No download URL in message")
            return
            
        # 5. Download File
        print("\nDownloading file...")
        # The URL is relative, prepend base
        full_url = "http://localhost:8000" + download_url
        
        # We don't strictly need auth for the download endpoint as implemented (it relies on the key),
        # but let's see. The code didn't check auth.
        dl_response = requests.get(full_url)
        
        if dl_response.status_code == 200:
            downloaded_content = dl_response.content
            print(f"Downloaded Content: {downloaded_content}")
            
            if downloaded_content == file_content:
                print("SUCCESS: Downloaded content matches original!")
            else:
                print("FAILURE: Content mismatch!")
                print(f"Expected: {file_content}")
                print(f"Got: {downloaded_content}")
        else:
            print(f"FAILURE: Download failed {dl_response.status_code}")
            
    except Exception as e:
        print(f"ERROR: History/Download failed: {e}")

def register_and_login(username):
    # Register
    requests.post(f"{BASE_URL}/auth/register", data={
        "username": username,
        "email": f"{username}@example.com",
        "password": "password",
        "full_name": "Test User"
    })
    # Login
    res = requests.post(f"{BASE_URL}/auth/token", data={
        "username": username,
        "password": "password"
    })
    data = res.json()
    return data['access_token'], data['user_id']

if __name__ == "__main__":
    test_file_share()
