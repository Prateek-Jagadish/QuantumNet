import sqlite3

conn = sqlite3.connect('quantumnet.db')
cursor = conn.cursor()

cursor.execute('SELECT username, password_hash, created_at FROM users WHERE username IN ("Prateek", "sada", "alice")')
users = cursor.fetchall()

print("User details:")
for u in users:
    print(f"\nUsername: {u[0]}")
    print(f"Hash: {u[1][:80]}...")
    print(f"Created: {u[2]}")

conn.close()
