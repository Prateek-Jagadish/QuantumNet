from app.core.security import verify_password, get_password_hash

# Test password hashing
test_password = "password"
test_hash = get_password_hash(test_password)
print(f"Test hash: {test_hash}")
print(f"Verification: {verify_password(test_password, test_hash)}")

# Test with actual stored hash for "Prateek"
stored_hash = "$2b$12$nUnp/zm75RQallvwOWU.j.NvsAFeOrwzFa1u.QQuYRw26U1/QV.wy"
print(f"\nVerifying 'password' against Prateek's hash: {verify_password('password', stored_hash)}")
