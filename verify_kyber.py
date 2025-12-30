import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from app.crypto import kyber
import binascii

def test_kyber():
    print("Testing Kyber-768 Implementation...")
    
    # 1. Generate Keypair
    print("Generating Keypair...")
    pk, sk = kyber.generate_keypair()
    print(f"Public Key Size: {len(pk)} bytes")
    print(f"Private Key Size: {len(sk)} bytes")
    
    # 2. Encapsulate
    print("Encapsulating...")
    ct, ss_alice = kyber.encapsulate(pk)
    print(f"Ciphertext Size: {len(ct)} bytes")
    print(f"Shared Secret (Alice): {binascii.hexlify(ss_alice).decode()}")
    
    # 3. Decapsulate
    print("Decapsulating...")
    ss_bob = kyber.decapsulate(ct, sk)
    print(f"Shared Secret (Bob):   {binascii.hexlify(ss_bob).decode()}")
    
    # 4. Verify
    if ss_alice == ss_bob:
        print("SUCCESS: Shared secrets match!")
    else:
        print("FAILURE: Shared secrets do NOT match!")
        sys.exit(1)

if __name__ == "__main__":
    test_kyber()
