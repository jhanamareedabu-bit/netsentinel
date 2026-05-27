import psycopg2

DATABASE_URL = "postgresql://postgres:iDJXpmjgDcpQdhfooDMyLYUXNarzVDJW@kodama.proxy.rlwy.net:11537/railway"

def get_conn():
    return psycopg2.connect(DATABASE_URL)
    sslmode="require"