import urllib.request
import json
import time
import sys

print("Waiting for server to start...")
time.sleep(5)

def test_endpoint(url):
    print(f"Testing {url}...")
    try:
        with urllib.request.urlopen(url) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                print(f"SUCCESS: Got {len(data)} items/keys")
                return data
            else:
                print(f"FAILURE: {response.status}")
                sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

base = "http://localhost:8000"
print("Verifying Security Metrics...")
metrics = test_endpoint(f"{base}/api/v1/security/metrics")
print(f"QBER: {metrics.get('qber')}")
print(f"Score: {metrics.get('security_score')}")

print("\nVerifying Security Events...")
test_endpoint(f"{base}/api/v1/security/events")

print("\nVerifying Active Keys...")
test_endpoint(f"{base}/api/v1/security/keys")

print("\nALL CHECKS PASSED")
