from database import get_cursor

with open("schema.sql", "r") as f:
    sql = f.read()

cur = get_cursor()
cur.execute(sql)

print("Database tables created successfully!")