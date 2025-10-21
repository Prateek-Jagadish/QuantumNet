#!/usr/bin/env python3
"""
Test script to check crypto library installation
"""

print("Testing crypto library installation...")

# Test 1: Try pycryptodome
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    print("✅ pycryptodome (Crypto) import successful")
    crypto_works = True
except ImportError as e:
    print(f"❌ pycryptodome (Crypto) import failed: {e}")
    crypto_works = False

# Test 2: Try cryptography library
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    print("✅ cryptography library import successful")
    crypto_lib_works = True
except ImportError as e:
    print(f"❌ cryptography library import failed: {e}")
    crypto_lib_works = False

# Test 3: Check installed packages
import subprocess
import sys

try:
    result = subprocess.run([sys.executable, '-m', 'pip', 'list'], capture_output=True, text=True)
    packages = result.stdout.lower()
    
    if 'pycryptodome' in packages:
        print("✅ pycryptodome is installed")
    else:
        print("❌ pycryptodome is NOT installed")
    
    if 'cryptography' in packages:
        print("✅ cryptography is installed")
    else:
        print("❌ cryptography is NOT installed")
        
except Exception as e:
    print(f"❌ Could not check installed packages: {e}")

# Test 4: Simple encryption test
if crypto_works:
    try:
        key = b'This is a test key for AES encryption!'
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        test_data = b'Hello, Quantum World!'
        padded_data = pad(test_data, 16)
        encrypted = cipher.encrypt(padded_data)
        print("✅ pycryptodome encryption test successful")
    except Exception as e:
        print(f"❌ pycryptodome encryption test failed: {e}")

print("\n" + "="*50)
print("SUMMARY:")
if crypto_works:
    print("✅ You can use pycryptodome")
elif crypto_lib_works:
    print("✅ You can use cryptography library")
else:
    print("❌ No crypto library is working properly")
    print("Try running: pip install pycryptodome cryptography")
