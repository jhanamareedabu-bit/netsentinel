from flask import Flask, render_template, request, redirect, session, Response
from database import get_conn
from camera import (
generate_frames,
save_snapshot,
start_recording,
stop_recording
)
from flask import redirect, url_for

from flask import send_from_directory
from datetime import timedelta
import os
import socket
import uuid

app = Flask(__name__)
app.secret_key = "secret123"

app.permanent_session_lifetime=timedelta(
minutes=15
)

print("RUNNING FILE:", __file__)

# LOGIN
@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_conn()
        cur = conn.cursor()

        try:
            cur.execute("""
                SELECT user_id, username, password_hash, status, failed_attempts, role, approval_status
                FROM Users
                WHERE username=%s
            """, (username,))

            user = cur.fetchone()

            if not user:
                cur.execute("""
                    INSERT INTO ActivityLogs(user_id, action_description, ip_address, log_type)
                    VALUES (%s, %s, %s, %s)
                """, (None, f"FAILED LOGIN - unknown user: {username}", request.remote_addr, "SYSTEM"))

                conn.commit()
                return "User not found"

            user_id, uname, db_pass, status, attempts, role, approval_status = user

            if approval_status != "Approved":
                return "Account waiting for Admin approval."

            if status == "Locked":
                return redirect(
                    "/support"
                )

            if password == db_pass:
                device_name = socket.gethostname()

                mac = uuid.getnode()

                mac = ':'.join(

                    [
                        '%012X' % mac
                    ][0][i:i + 2]

                    for i in range(
                        0,
                        12,
                        2
                    )

                )

                cur.execute("""
                

                            INSERT INTO Devices(device_name,
                                                ip_address,
                                                mac_address,
                                                user_id)

                            VALUES (%s,
                                    %s,
                                    %s,
                                    %s)

                            """, (

                                device_name,
                                request.remote_addr,
                                mac,
                                user_id

                            ))

                cur.execute("""
                    UPDATE Users
                    SET failed_attempts = 0
                    WHERE user_id = %s
                """, (user_id,))

                cur.execute("""
                    INSERT INTO ActivityLogs(user_id, action_description, ip_address, log_type)
                    VALUES (%s, %s, %s, %s)
                """, (user_id, "LOGIN SUCCESS", request.remote_addr, "AUTH"))

                cur.execute("""

                            SELECT last_login_ip

                            FROM Users

                            WHERE user_id = %s

                            """, (user_id,))

                old_ip = cur.fetchone()[0]

                if old_ip and old_ip != request.remote_addr:
                    cur.execute("""

                                INSERT INTO Notifications(user_id,
                                                          message)

                                VALUES (%s,
                                        %s)

                                """, (

                                    user_id,

                                    "Suspicious Login New IP"

                                ))

                    cur.execute("""

                                UPDATE Users

                                SET last_login_ip=%s,

                                    last_login_time=NOW()

                                WHERE user_id = %s

                                """, (

                                    request.remote_addr,
                                    user_id

                                ))


                conn.commit()

                session.permanent = True

                session["user_id"] = user_id
                session["user"] = username
                session["role"] = role

                return redirect("/dashboard")

            else:

                attempts += 1
                status_update = "Locked" if attempts >= 3 else "Active"

                cur.execute("""
                    UPDATE Users
                    SET failed_attempts = %s,
                        status = %s
                    WHERE user_id = %s
                """, (attempts, status_update, user_id))

                cur.execute("""
                    INSERT INTO ActivityLogs(user_id, action_description, ip_address, log_type)
                    VALUES (%s, %s, %s, %s)
                """, (user_id, f"LOGIN FAILED attempt {attempts}", request.remote_addr, "AUTH"))

                conn.commit()

                return f"Wrong password. Attempt {attempts}/3"

        finally:
            cur.close()
            conn.close()

    return render_template("login.html")

@app.route("/logout")
def logout():

    conn=get_conn()
    cur=conn.cursor()

    if session.get("user_id"):

        cur.execute("""

        INSERT INTO ActivityLogs(

        user_id,

        action_description,

        ip_address,

        log_type

        )

        VALUES(

        %s,

        %s,

        %s,

        %s

        )

        """,(

        session["user_id"],

        "LOGOUT",

        request.remote_addr,

        "AUTH"

        ))

        conn.commit()

    cur.close()
    conn.close()

    session.clear()

    return redirect("/")

@app.route("/register", methods=["GET","POST"])
def register():

    if request.method=="POST":

        username=request.form["username"]
        fullname=request.form["fullname"]
        password=request.form["password"]

        conn=get_conn()
        cur=conn.cursor()

        try:

            cur.execute("""

            INSERT INTO Users(

            username,
            full_name,
            password_hash,
            role,
            status,
            approval_status,
            failed_attempts

            )

            VALUES(

            %s,
            %s,
            %s,
            'User',
            'Active',
            'Pending',
            0

            )

            """,(

            username,
            fullname,
            password

            ))

            conn.commit()

            return """

            Account Created

            Wait Admin Approval

            <br><br>

            <a href='/'>
            Login
            </a>

            """

        finally:

            cur.close()
            conn.close()

    return render_template(
    "register.html"
    )

# DASHBOARD USER ONLy
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()

    # ADMIN DASHBOARD LOGS

    if session["role"] == "Admin":

        cur.execute("""
            SELECT
                COALESCE(Users.username,'SYSTEM'),
                action_description,
                timestamp
            FROM ActivityLogs
            LEFT JOIN Users
            ON Users.user_id=ActivityLogs.user_id
            ORDER BY timestamp DESC
            LIMIT 10
        """)

        logs = cur.fetchall()

        # KPIs ADMIN ONLY
        cur.execute("SELECT COUNT(*) FROM Users")
        users = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM ActivityLogs")
        total_logs = cur.fetchone()[0]

    # USER DASHBOARD LOGS

    else:

        cur.execute("""
            SELECT
                action_description,
                timestamp
            FROM ActivityLogs
            WHERE user_id=%s
            ORDER BY timestamp DESC
            LIMIT 10
        """, (session["user_id"],))

        logs = cur.fetchall()

        # KPIs USER ONLY
        cur.execute("SELECT COUNT(*) FROM ActivityLogs WHERE user_id=%s",
                    (session["user_id"],))
        total_logs = cur.fetchone()[0]

        users = None

    cur.close()
    conn.close()

    camera_status = "ONLINE"

    return render_template(
        "dashboard.html",
        logs=logs,
        role=session["role"],
        camera_status=camera_status,
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

    # REQUESTS
    cur.execute("SELECT COUNT(*) FROM Requests WHERE status='PENDING'")
    pending_requests = cur.fetchone()[0]

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
        pending_requests=pending_requests,
        auth_logs=auth_logs
    )

@app.route("/alllogs")
def alllogs():

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

    if "user" not in session:
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()

    user_id = session["user_id"]

    cur.execute("""
        SELECT action_description, ip_address, log_type, timestamp
        FROM ActivityLogs
        WHERE user_id = %s
        ORDER BY timestamp DESC
    """, (user_id,))

    data = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("logs.html", logs=data)

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

@app.route("/notifications")
def notifications():

    if session.get("role")!="Admin":
        return "Access Denied"

    conn=get_conn()
    cur=conn.cursor()

    cur.execute("""

    SELECT

    Users.username,
    Notifications.message,
    Notifications.created_at

    FROM Notifications

    JOIN Users

    ON Users.user_id=
    Notifications.user_id

    ORDER BY created_at DESC

    """)

    data=cur.fetchall()

    cur.close()
    conn.close()

    return render_template(

    "notifications.html",

    data=data

    )

# CCTV PAGE
@app.route("/cctv")
def cctv():

    if "user" not in session:
        return redirect("/")

    base_dir = app.root_path

    images_path = os.path.join(base_dir, "snapshots")
    recordings_path = os.path.join(base_dir, "recordings")

    images = []
    files = []

    if os.path.exists(images_path):
        images = os.listdir(images_path)
        images.sort(reverse=True)

    if os.path.exists(recordings_path):
        files = os.listdir(recordings_path)
        files.sort(reverse=True)

    return render_template(
        "cctv.html",
        images=images,
        files=files
    )

# VIDEO FEED
@app.route("/video_feed")
def video_feed():

    return Response(
        generate_frames(),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )

@app.route("/snapshot")
def snapshot():

    if "user" not in session:
        return redirect("/")

    filename=save_snapshot()

    conn=get_conn()
    cur=conn.cursor()

    cur.execute("""

        INSERT INTO ActivityLogs(
            user_id,
            action_description,
            ip_address,
            log_type
        )

        VALUES(
            %s,
            %s,
            %s,
            %s
        )

    """,(

        session["user_id"],
        f"SNAPSHOT SAVED {filename}",
        request.remote_addr,
        "CAMERA"

    ))

    conn.commit()

    cur.close()
    conn.close()

    return f"""
    Snapshot Saved

    File:

    {filename}

    <a href='/history'>
    Open History
    </a>

    <br>

    <a href='/cctv'>
    Back CCTV
    </a>
    """

@app.route("/snapshots/<filename>")
def snapshots(filename):

    return send_from_directory(
        "snapshots",
        filename
    )


@app.route("/history")
def history():

    if "user" not in session:
        return redirect("/")

    files=os.listdir(
        "snapshots"
    )

    files.sort(
        reverse=True
    )

    return render_template(
        "history.html",
        images=files
    )

@app.route("/snapshot/<filename>")
def view_snapshot(filename):

    return send_from_directory(
        "snapshots",
        filename
    )
@app.route("/record/start")
def record_start():

    if session.get(
    "role"
    )!="Admin":

        return "Denied"

    start_recording()

    return redirect(
    "/cctv"
    )


@app.route("/record/stop")
def record_stop():

    if session.get(
    "role"
    )!="Admin":

        return "Denied"

    stop_recording()

    return redirect(
    "/cctv"
    )

@app.route("/recordings")
def recordings_page():

    if "user" not in session:
        return redirect("/")

    files = []

    if os.path.exists("recordings"):
        files = os.listdir("recordings")
        files.sort(reverse=True)

    return render_template(
        "recordings.html",
        files=files
    )

@app.route("/recordings/<filename>")
def view_recording(filename):

    folder = os.path.join(app.root_path, "recordings")

    return send_from_directory(
        folder,
        filename,
        as_attachment=False
    )

@app.route("/recordings/view/<filename>")
def view_recording_page(filename):

    return render_template(
        "view_recording.html",
        filename=filename
    )

@app.route("/debug-recordings")
def debug_recordings():

    import os

    base_dir = os.path.dirname(os.path.abspath(__file__))
    folder = os.path.join(base_dir, "recordings")

    return {
        "base_dir": base_dir,
        "folder": folder,
        "exists": os.path.exists(folder),
        "files": os.listdir(folder) if os.path.exists(folder) else []
    }

@app.route("/play_recording/<filename>")
def play_recording(filename):

    return render_template("play_recording.html", filename=filename)

@app.route("/delete_snapshot/<filename>")
def delete_snapshot(filename):

    if "user" not in session:
        return redirect("/")

    file_path = os.path.join("snapshots", filename)

    if os.path.exists(file_path):
        os.remove(file_path)

    return redirect("/cctv")

# DELETE RECORDING
@app.route("/delete_recording/<filename>")
def delete_recording(filename):

    if session.get("role") != "Admin":
        return "Denied"

    file_path = os.path.join("recordings", filename)

    if os.path.exists(file_path):
        os.remove(file_path)

    return redirect("/cctv")


@app.route("/forgot", methods=["GET", "POST"])
def forgot():

    if request.method == "POST":

        username = request.form["username"]

        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
            SELECT user_id
            FROM Users
            WHERE username = %s
        """, (username,))

        user = cur.fetchone()

        if user:

            cur.execute("""
                INSERT INTO PasswordResetRequests(
                    user_id,
                    status,
                    created_at
                )
                VALUES (%s, 'Pending', NOW())
            """, (user[0],))

            conn.commit()

        cur.close()
        conn.close()

        return "Request Sent. Wait Admin Approval"

    return render_template("forgot.html")

@app.route("/password_resets")
def password_resets():

    if session.get("role") != "Admin":
        return "Denied"

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, user_id, status, created_at
        FROM PasswordResetRequests
        ORDER BY created_at DESC
    """)

    data = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("password_resets.html", data=data)

@app.route("/reset/approve/<int:req_id>")
def approve_reset(req_id):

    if session.get("role") != "Admin":
        return "Denied"

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        UPDATE PasswordResetRequests
        SET status = 'Approved'
        WHERE id = %s
    """, (req_id,))

    conn.commit()
    cur.close()
    conn.close()

    return redirect("/password_resets")

@app.route("/reset/reject/<int:req_id>")
def reject_reset(req_id):

    if session.get("role") != "Admin":
        return "Denied"

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        UPDATE PasswordResetRequests
        SET status = 'Rejected'
        WHERE id = %s
    """, (req_id,))

    conn.commit()
    cur.close()
    conn.close()

    return redirect("/password_resets")

@app.route("/support", methods=["GET","POST"])
def support():

    if request.method == "POST":

        message = request.form["message"]

        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO Requests(user_id, request_type, message, status)
            VALUES (%s, 'TECH_SUPPORT', %s, 'PENDING')
        """, (session["user_id"], message))

        conn.commit()

        cur.close()
        conn.close()

        return "Request Sent"

    return render_template("support.html")

@app.route(
"/supportadmin"
)

def supportadmin():

    if session.get(
    "role"
    )!="Admin":

        return "Denied"

    conn=get_conn()
    cur=conn.cursor()

    cur.execute("""

    SELECT

    Users.username,

    SupportRequests.message,

    SupportRequests.status

    FROM SupportRequests

    LEFT JOIN Users

    ON Users.user_id=
    SupportRequests.user_id

    ORDER BY
    created_at DESC

    """)

    data=cur.fetchall()

    cur.close()
    conn.close()

    return render_template(

    "support_admin.html",

    requests=data

    )

@app.route("/requests")
def requests():

    if session.get("role") != "Admin":
        return "Denied"

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, user_id, request_type, message, status, created_at
        FROM Requests
        ORDER BY created_at DESC
    """)

    data = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("requests.html", data=data)


@app.route("/recordings")
def recordings():

    if session.get(
    "role"
    )!="Admin":

        return "Denied"

    files=os.listdir(
    "recordings"
    )

    files.sort(
    reverse=True
    )

    return render_template(

    "recordings.html",

    files=files

    )

# RUN APP
if __name__ == "__main__":
    app.run(debug=True)