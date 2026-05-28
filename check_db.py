from database import get_conn

conn = get_conn()
cur = conn.cursor()

cur.execute("""
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'users'
AND column_name = 'password_hash'
""")

print("PASSWORD_HASH CHECK:", cur.fetchall())

cur.close()
conn.close()