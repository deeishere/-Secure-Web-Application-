import sqlite3
import bleach
import os                                    # Part 1: needed for os.urandom
from flask import Flask, render_template, request, session, redirect, url_for
from cryptography.fernet import Fernet       # Part 3: needed for email encryption

app = Flask(__name__)

# ── Encryption Part 1: Secure Secret Key ─────────────────────
# VULNERABLE: app.secret_key = "temporary-dev-key"
# Hardcoded keys let anyone who reads the source forge session cookies.
# SECURE: os.urandom(24) generates a random unpredictable key every run.
app.secret_key = os.urandom(24)

# ── Encryption Part 3: Fernet setup ──────────────────────────
# Generate key once, then store it in fernet.key

KEY_FILE = "fernet.key"

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        FERNET_KEY = f.read()
else:
    FERNET_KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(FERNET_KEY)

fernet = Fernet(FERNET_KEY)


def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    # Added email column to store Fernet-encrypted email
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            comment TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Render the registration form, register user, and demonstrate both query styles + encryption."""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email    = request.form.get("email")        # Part 3: get email from form
        conn = None

        try:
            conn = get_db()
            
            # ── Encryption Part 3: Encrypt email before saving ───
            # VULNERABLE: plaintext email exposes user data if DB is breached.
            # SECURE: fernet.encrypt() encrypts email; .decode() converts bytes → string for SQLite.
            encrypted_email = fernet.encrypt(email.encode()).decode()

            # ─────────────────────────────────────────────
            # NOTE: This query is intentionally vulnerable for security practice.
            # query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

            # SECURE VERSION (used in app)
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
            user = conn.execute(query, (username, password)).fetchone()

            # ─────────────────────────────────────────────
            # Part 3: Encrypt email before saving
            # VULNERABLE: plaintext email exposes user data if DB is breached.
            # SECURE: fernet.encrypt() encrypts email; .decode() converts bytes → string for SQLite.

            # Insert user (only if not exists / or you can decide logic)
            existing_user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if existing_user:
                return "Username already exists. Please choose another username."

            # Insert user (only if not exists / or you can decide logic)
            conn.execute(
                "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                (username, password, encrypted_email)
            )

            conn.commit()
            return redirect(url_for("login"))

        except sqlite3.Error:
            return "Registration failed due to a database error.", 500

        finally:
            if conn:
                conn.close()

    return render_template("register.html")


SQL_INJECTION_MODE = False  # set to True to enable vulnerable mode

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login route demonstrating secure vs vulnerable SQL handling."""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = None

        try:
            conn = get_db()

            # ─────────────────────────────────────────────
            if SQL_INJECTION_MODE:
                # ❌ VULNERABLE VERSION (for SQL injection testing only)
                query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                user = conn.execute(query).fetchone()

            else:
                # ✅ SECURE VERSION (production-safe)
                user = conn.execute(
                    "SELECT * FROM users WHERE username = ? AND password = ?",
                    (username, password),
                ).fetchone()

            # ─────────────────────────────────────────────

            if user:
                session["username"] = username
                session["role"] = user["role"]
                return redirect(url_for("dashboard"))
        
            return render_template("login.html", error_message="Invalid username or password.")

        except sqlite3.Error:
            return "Login failed due to a database error.", 500

        finally:
            if conn:
                conn.close()

    return render_template("login.html", error_message=None)


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    comments = conn.execute("SELECT * FROM comments").fetchall()

    # ── Encryption Part 3: Decrypt email for display ─────────
    # fernet.decrypt() reverses the encryption to show the real email.
    user = conn.execute(
        "SELECT email FROM users WHERE username = ?",
        (session["username"],)
    ).fetchone()
    conn.close()

    decrypted_email = ""
    if user and user["email"]:
        decrypted_email = fernet.decrypt(user["email"].encode()).decode()

    return render_template(
        "dashboard.html",
        username=session["username"],
        email=decrypted_email,
        comments=comments
    )


@app.route("/comment", methods=["POST"])
def add_comment():
    if "username" not in session:
        return redirect(url_for("login"))

    raw_comment = request.form.get("comment")

    # Vulnerable version - XSS:
    # This saves user input without sanitization.
    # Example attack: <script>alert("XSS")</script>
    # clean_comment = raw_comment

    # Secure version - XSS mitigation:
    # bleach.clean() sanitizes the input and removes dangerous scripts.
    clean_comment = bleach.clean(raw_comment)

    conn = get_db()
    conn.execute(
        "INSERT INTO comments (username, comment) VALUES (?, ?)",
        (session["username"], clean_comment)
    )
    conn.commit()
    conn.close()

    return redirect(url_for("dashboard"))

# ── Role-based access control decorator ──────────────────────
from functools import wraps
from flask import abort

SECURE_MODE = True  # set to False to demo the vulnerability

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not SECURE_MODE:
                return f(*args, **kwargs)  # vulnerable: no check

            if "username" not in session:
                return redirect(url_for("login"))

            if session.get("role") != role:
                abort(403)  # secure: wrong role → forbidden

            return f(*args, **kwargs)
        return decorated
    return decorator


@app.route("/admin")
@role_required("admin")
def admin():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()

    return render_template("admin.html", users=users)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    # ── Encryption Part 2: Enable HTTPS ──────────────────────
    # VULNERABLE: app.run(debug=True) uses plain HTTP — data travels unencrypted.
    # SECURE: ssl_context='adhoc' generates a self-signed TLS certificate so all
    # traffic between browser and server is encrypted in transit.
    app.run(debug=True, ssl_context='adhoc')
