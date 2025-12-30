import requests

# Try login with sada
print("Testing login with 'sada'...")
r = requests.post('http://127.0.0.1:8000/api/v1/auth/token', data={'username': 'sada', 'password': 'password'})
print(f"Status: {r.status_code}")

if r.status_code == 200:
    token = r.json().get('access_token')
    print(f"Token received: {token[:30]}...")
    
    # Test search
    print("\nSearching for 'Prateek'...")
    headers = {'Authorization': f'Bearer {token}'}
    resp = requests.get('http://127.0.0.1:8000/api/v1/contacts/search?query=Prateek', headers=headers)
    print(f"Search status: {resp.status_code}")
    if resp.status_code == 200:
        results = resp.json()
        print(f"Found {len(results)} users:")
        for u in results:
            print(f"  - {u['username']} ({u['full_name']})")
    else:
        print(f"Error: {resp.text}")
else:
    print(f"Login failed: {r.text}")
