from flask import Flask, render_template, request, redirect, session, Response
from datetime import timedelta, datetime
import socket
import uuid

from camera import generate_frames
from database import get_conn

import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

MAX_ATTEMPTS = 3

app = Flask(
    __name__,
    static_folder="static",
    static_url_path="/static"
)

app.secret_key = "secret123"

app.permanent_session_lifetime=timedelta(
minutes=15
)

logs = []
users = 0
total_logs = 0


print("RUNNING FILE:", __file__)

# LOGIN
@app.route("/", methods=["GET", "POST"])
def login():

    # if already logged in, go dashboard
    if request.method == "GET":
        if "user_id" in session:
            return redirect("/dashboard")
        return render_template("login.html")

    # POST LOGIN
    username = request.form["username"]
    password = request.form["password"]

    conn = get_conn()
    cur = conn.cursor()

    try:
        # FETCH USER
        cur.execute("""
            SELECT user_id, username, password_hash, status,
                   failed_attempts, role, approval_status
            FROM Users
            WHERE username=%s
        """, (username,))

        user = cur.fetchone()

        # USER NOT FOUND
        if not user:
            cur.execute("""
                INSERT INTO ActivityLogs(user_id, action_description, ip_address, log_type)
                VALUES (%s, %s, %s, %s)
            """, (None, f"FAILED LOGIN - unknown user: {username}", request.remote_addr, "AUTH"))

            conn.commit()
            return render_template("login.html", error="Invalid credentials")

        user_id, uname, password_hash, status, attempts, role, approval_status = user

        # NOT APPROVED
        if approval_status != "Approved":
            return render_template("login.html", error="Account pending admin approval")

        # LOCKED ACCOUNT
        if status == "Locked":
            return render_template("login.html", error="Account locked. Contact admin")

        # PASSWORD CHECK
        password_match = check_password(password, password_hash)

        # SUCCESS LOGIN
        if password_match:

            # reset failed attempts
            cur.execute("""
                UPDATE Users
                SET failed_attempts = 0
                WHERE user_id = %s
            """, (user_id,))

            # device logging
            device_name = socket.gethostname()
            mac = ':'.join(['%012X' % uuid.getnode()][0][i:i+2] for i in range(0, 12, 2))

            cur.execute("""
                INSERT INTO Devices(device_name, ip_address, mac_address, user_id)
                VALUES (%s, %s, %s, %s)
            """, (device_name, request.remote_addr, mac, user_id))

            # activity log
            cur.execute("""
                INSERT INTO ActivityLogs(user_id, action_description, ip_address, log_type)
                VALUES (%s, %s, %s, %s)
            """, (user_id, "LOGIN SUCCESS", request.remote_addr, "AUTH"))

            conn.commit()

            # CLEAN SESSION
            session.clear()
            session.permanent = True

            session["user_id"] = user_id
            session["role"] = role
            session["ip"] = request.remote_addr
            session["last_active"] = datetime.now().timestamp()

            return redirect("/dashboard")

        # FAILED LOGIN HANDLING
        attempts += 1

        if attempts >= 3:
            status_update = "Locked"

            feedback = "Account locked due to 3 failed attempts. Please contact admin."
        else:
            status_update = "Active"

            if attempts == 2:
                feedback = "⚠️ Warning: Last attempt remaining before account lock!"
            else:
                feedback = f"Wrong password. Attempt {attempts}/3"

        cur.execute("""
            UPDATE Users
            SET failed_attempts = %s,
                status = %s
            WHERE user_id = %s
        """, (attempts, status_update, user_id))

        cur.execute("""
            INSERT INTO ActivityLogs(user_id, action_description, ip_address, log_type)
            VALUES (%s, %s, %s, %s)
        """, (user_id, f"LOGIN FAILED ({attempts}/3)", request.remote_addr, "AUTH"))

        conn.commit()

        return feedback

    finally:
        cur.close()
        conn.close()

@app.route("/logout")

def logout():

    conn = get_conn()
    cur = conn.cursor()

    if session.get("user_id"):

        cur.execute("""
            INSERT INTO ActivityLogs(user_id, action_description)
            VALUES (%s, %s)
        """, (session["user_id"], "LOGOUT"))

        conn.commit()

    cur.close()
    conn.close()

    session.clear()
    return redirect("/")

@app.route("/register", methods=["GET","POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        fullname = request.form["fullname"]
        password = request.form["password"]

        conn = get_conn()
        cur = conn.cursor()

        try:
            hashed_pw = hash_password(password)

            cur.execute("""
                INSERT INTO Users(
                    username,
                    full_name,
                    password_hash,
                    role,
                    status,
                    failed_attempts
                )
                VALUES (%s, %s, %s, 'User', 'Active', 0)
            """, (username, fullname, hashed_pw))

            conn.commit()

            return "Account Created"

        finally:
            cur.close()
            conn.close()

    return render_template("register.html")

@app.before_request
def security_guard():

    public_routes = ["/", "/register"]

    if request.endpoint == "login":
        return

    if request.path.startswith("/static"):
        return

    if request.path in public_routes:
        return

    if "user_id" not in session:
        return redirect("/")

    # IP MATCH
    if session.get("ip") != request.remote_addr:
        session.clear()
        return redirect("/")

    # TIMEOUT CHECK
    last_active = session.get("last_active")

    if last_active:
        elapsed = datetime.now().timestamp() - last_active

        if elapsed > 900:  # 15 minutes
            session.clear()
            return redirect("/")

    # update activity timestamp
    session["last_active"] = datetime.now().timestamp()

# DASHBOARD USER ONLy
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()

    # ADMIN DASHBOARD
    if session["role"] == "Admin":

        # RECENT LOGS
        cur.execute("""

            SELECT
                COALESCE(Users.username,'SYSTEM'),
                action_description,
                ip_address,
                log_type,
                timestamp

            FROM ActivityLogs

            LEFT JOIN Users
            ON Users.user_id = ActivityLogs.user_id

            ORDER BY timestamp DESC
            LIMIT 10

        """)

        logs = cur.fetchall()

        # TOTAL USERS
        cur.execute("SELECT COUNT(*) FROM Users")
        users = cur.fetchone()[0]

        # TOTAL LOGS
        cur.execute("SELECT COUNT(*) FROM ActivityLogs")
        total_logs = cur.fetchone()[0]

    # USER DASHBOARD
    else:

        cur.execute("""

            SELECT
                action_description,
                ip_address,
                log_type,
                timestamp

            FROM ActivityLogs

            WHERE user_id=%s

            ORDER BY timestamp DESC
            LIMIT 10

        """, (session["user_id"],))

        logs = cur.fetchall()

        cur.execute("""
            SELECT COUNT(*)
            FROM ActivityLogs
            WHERE user_id=%s
        """, (session["user_id"],))

        total_logs = cur.fetchone()[0]

        users = None

    cur.close()
    conn.close()

    return render_template(
        "dashboard.html",
        logs=logs,
        total_logs=total_logs,
        users=users
    )

@app.route("/admin/dashboard")
def admin_dashboard():

    if session.get("role") != "Admin":
        return "Denied"

    conn = get_conn()
    cur = conn.cursor()

    # USERS
    cur.execute("SELECT COUNT(*) FROM Users")
    total_users = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM Users WHERE status='Active'")
    active_users = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM Users WHERE status='Locked'")
    locked_users = cur.fetchone()[0]

    # LOGS
    cur.execute("SELECT COUNT(*) FROM ActivityLogs WHERE log_type='AUTH'")
    auth_logs = cur.fetchone()[0]

    cur.close()
    conn.close()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        active_users=active_users,
        locked_users=locked_users,
        auth_logs=auth_logs
    )

@app.route("/all-logs")
def all_logs():

    if session.get("role")!="Admin":
        return "Access Denied"

    conn=get_conn()
    cur=conn.cursor()

    cur.execute("""

        SELECT
            COALESCE(Users.username,'SYSTEM'),
            action_description,
            ip_address,
            log_type,
            timestamp

        FROM ActivityLogs

        LEFT JOIN Users
        ON Users.user_id=ActivityLogs.user_id

        ORDER BY timestamp DESC

    """)

    logs=cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "alllogs.html",
        logs=logs
    )

# USER FULL LOGS
@app.route("/logs")
def logs():

    if "user_id" not in session:
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()

    user_id = session["user_id"]

    cur.execute("""

        SELECT
            action_description,
            ip_address,
            log_type,
            timestamp

        FROM ActivityLogs

        WHERE user_id = %s

        ORDER BY timestamp DESC

    """, (user_id,))

    data = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "logs.html",
        logs=data
    )

# ADMIN PANEL
@app.route("/admin")
def admin():

    if session.get("role")!="Admin":
        return "Access Denied"

    conn=get_conn()
    cur=conn.cursor()

    cur.execute("""

        SELECT
        user_id,
        username,
        role,
        status,
        approval_status,
        failed_attempts

        FROM Users

        ORDER BY user_id

    """)

    users=cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "admin.html",
        users=users
    )

# APPROVE USER
@app.route("/approve/<int:user_id>")
def approve(user_id):

    if session.get("role") != "Admin":
        return "Access Denied"

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        UPDATE Users
        SET approval_status='Approved'
        WHERE user_id=%s
    """, (user_id,))

    cur.execute("""
        INSERT INTO ActivityLogs(user_id, action_description, ip_address, log_type)
        VALUES (%s, %s, %s, %s)
    """, (user_id, "ACCOUNT APPROVED", request.remote_addr, "ADMIN"))

    conn.commit()

    cur.close()
    conn.close()

    return redirect("/admin")

# BLOCK USER
@app.route("/block/<int:user_id>")
def block(user_id):

    if session.get("role") != "Admin":
        return "Access Denied"

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        UPDATE Users
        SET status='Locked'
        WHERE user_id=%s
    """, (user_id,))

    cur.execute("""
        INSERT INTO ActivityLogs(user_id, action_description, ip_address, log_type)
        VALUES (%s, %s, %s, %s)
    """, (user_id, "ACCOUNT BLOCKED BY ADMIN", request.remote_addr, "ADMIN"))

    conn.commit()

    cur.close()
    conn.close()

    return redirect("/admin")

# UNLOCK USER
@app.route("/unlock/<int:user_id>")
def unlock(user_id):

    if session.get("role") != "Admin":
        return "Access Denied"

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        UPDATE Users
        SET status='Active',
            failed_attempts=0
        WHERE user_id=%s
    """, (user_id,))

    cur.execute("""
        INSERT INTO ActivityLogs(user_id, action_description, ip_address, log_type)
        VALUES (%s, %s, %s, %s)
    """, (user_id, "ACCOUNT UNLOCKED BY ADMIN", request.remote_addr, "ADMIN"))

    conn.commit()

    cur.close()
    conn.close()

    return redirect("/admin")

# VIDEO FEED
@app.route("/video_feed")
def video_feed():

    return Response(
        generate_frames(),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )

# RUN APP
if __name__ == "__main__":
    app.run(debug=True)