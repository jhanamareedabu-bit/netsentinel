from database import get_conn
import bcrypt

# 🔐 hash function
def hash_pw(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# 👤 seed users
users = [
    ("jhana_admin", "Jhana#NetSentinel_2403!", "Admin", "Jhana Dela Cruz"),
    ("tinay_admin", "Cristina#NetSentinel_2403!", "Admin", "Cristina Garcia"),
    ("danna_admin", "Danna#NetSentinel_2403!", "Admin", "Danna Sarmiento"),
    ("loraigne_admin", "Loraigne#NetSentinel_2403!", "Admin", "Loraigne Petalver"),
    ("noah_admin", "Noah#NetSentinel_2403!", "Admin", "Noah Bombane"),
    ("demo_user", "User#Demo_2403!", "User", "Demo User")
]

conn = get_conn()
cur = conn.cursor()

try:
    for username, password, role, fullname in users:

        hashed = hash_pw(password)

        # prevents duplicates
        cur.execute("""
            INSERT INTO Users (
                username,
                full_name,
                password_hash,
                role,
                status,
                failed_attempts,
                approval_status
            )
            VALUES (%s, %s, %s, %s, 'Active', 0, 'Approved')
            ON CONFLICT (username)
            DO UPDATE SET
                full_name = EXCLUDED.full_name,
                password_hash = EXCLUDED.password_hash,
                role = EXCLUDED.role,
                status = 'Active',
                failed_attempts = 0,
                approval_status = 'Approved'
        """, (
            username,
            fullname,
            hashed,
            role
        ))

    conn.commit()
    print("Seed completed successfully")

except Exception as e:
    conn.rollback()
    print("Error during seeding:", e)

finally:
    cur.close()
    conn.close()