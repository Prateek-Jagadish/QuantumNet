import sqlite3

conn = sqlite3.connect('quantumnet.db')
cursor = conn.cursor()

cursor.execute('SELECT username, password_hash, LENGTH(password_hash) as hash_len FROM users WHERE username IN ("Prateek", "sada", "alice")')
users = cursor.fetchall()

print("Full hash details:")
for u in users:
    print(f"\nUsername: {u[0]}")
    print(f"Hash length: {u[2]} chars (should be 60)")
    print(f"Full hash: {u[1]}")

conn.close()
