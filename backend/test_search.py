import requests
import json

BASE_URL = "http://127.0.0.1:8000/api/v1"

# Step 1: Login as Prateek
print("Step 1: Logging in as Prateek...")
login_data = {
    "username": "Prateek",
    "password": "password"
}
response = requests.post(f"{BASE_URL}/auth/token", data=login_data)
print(f"Login Status: {response.status_code}")
if response.status_code == 200:
    token_data = response.json()
    token = token_data.get("access_token")
    print(f"Token: {token[:50]}...")
else:
    print(f"Login failed: {response.text}")
    exit(1)

# Step 2: Search for "sada"
print("\nStep 2: Searching for 'sada'...")
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(f"{BASE_URL}/contacts/search?query=sada", headers=headers)
print(f"Search Status: {response.status_code}")
if response.status_code == 200:
    results = response.json()
    print(f"Found {len(results)} users:")
    for user in results:
        print(f"  - {user['username']} ({user['full_name']})")
else:
    print(f"Search failed: {response.text}")

# Step 3: Search for "Prateek" (should find 0 since we exclude current user)
print("\nStep 3: Searching for 'Prateek' (should be excluded)...")
response = requests.get(f"{BASE_URL}/contacts/search?query=Prateek", headers=headers)
print(f"Search Status: {response.status_code}")
if response.status_code == 200:
    results = response.json()
    print(f"Found {len(results)} users (should be 0):")
    for user in results:
        print(f"  - {user['username']} ({user['full_name']})")
