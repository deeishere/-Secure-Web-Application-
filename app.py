import sqlite3
import bleach
import os                                    # Part 1: needed for os.urandom / environ
from flask import Flask, render_template, request, session, redirect, url_for
from cryptography.fernet import Fernet       # Part 3: needed for email encryption
from flask_bcrypt import Bcrypt
from functools import wraps
from flask import abort


app = Flask(__name__)

# Initialize Bcrypt for secure password hashing.
# We use bcrypt because it automatically handles 'salting' and has a 'work factor'
# to slow down brute-force attacks compared to MD5 or SHA-1
bcrypt = Bcrypt(app)

# ── Encryption Part 1: Secure Secret Key ─────────────────────
# VULNERABLE: app.secret_key = "temporary-dev-key"
# Hardcoded keys let anyone who reads the source forge session cookies.
# SECURE: Read from environment variable so the key survives server restarts.
# Falls back to os.urandom(24) if SECRET_KEY is not set (fine for dev, not production).
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# ── Encryption Part 3: Fernet setup ──────────────────────────
# Generate key once, then persist it in fernet.key so encrypted emails
# remain decryptable across server restarts.
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

    # Added email column to store Fernet-encrypted email.
    # username is UNIQUE at the DB level as a second safety net
    # (a manual check also exists inside register() for a user-friendly message).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
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


# ── SQL Injection mode flag ───────────────────────────────────
# Set to True to demo the vulnerable version on BOTH register and login.
# Set to False (default) for the secure, production-safe version.
SQL_INJECTION_MODE = False


@app.route("/register", methods=["GET", "POST"])
def register():
    """Render the registration form and demonstrate secure vs vulnerable SQL + encryption."""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email    = request.form.get("email")        # Part 3: get email from form
        conn = None

        try:
            conn = get_db()

            if SQL_INJECTION_MODE:
                # ── VULNERABLE VERSION (SQL Injection demo) ───────────
                # String formatting allows malicious input, e.g.: admin'--
                # Passwords stored as plaintext — never do this in production.
                query = f"SELECT * FROM users WHERE username = '{username}'"
                existing_user = conn.execute(query).fetchone()

                if existing_user:
                    return render_template(
                    "register.html",
                    error_message="Username already exists. Please choose another username."
                )

                conn.execute(
                    f"INSERT INTO users (username, password, email) "
                    f"VALUES ('{username}', '{password}', '{email}')"
                )
                conn.commit()
                return redirect(url_for("login"))

            # ── SECURE VERSION ────────────────────────────────────────

            # ── Encryption Part 3: Encrypt email before saving ────────
            # VULNERABLE: plaintext email exposes user data if DB is breached.
            # SECURE: fernet.encrypt() encrypts email; .decode() converts bytes to string for SQLite.
            encrypted_email = fernet.encrypt(email.encode()).decode()

            # ── Password Storage: bcrypt hashing ─────────────────────
            # VULNERABLE: Storing password as plaintext or MD5 exposes user credentials.
            # SECURE: bcrypt.generate_password_hash creates a unique salted hash per user.
            # Even two identical passwords produce different hashes — resistant to rainbow tables.
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Manual duplicate check gives a friendly error message before the DB constraint fires.
            existing_user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if existing_user:
                return render_template(
                    "register.html",
                    error_message="Username already exists. Please choose another username."
                )

            conn.execute(
                "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                (username, hashed_password, encrypted_email)
            )

            conn.commit()
            return redirect(url_for("login"))

        except sqlite3.Error:
            return "Registration failed due to a database error.", 500

        finally:
            if conn:
                conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login route demonstrating secure vs vulnerable SQL handling."""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = None

        try:
            conn = get_db()

            if SQL_INJECTION_MODE:
                # ── VULNERABLE VERSION (SQL Injection demo) ───────────
                # String formatting + plaintext password comparison — easily bypassed.
                # Example payload: ' OR '1'='1'--
                query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                user = conn.execute(query).fetchone()

                if user:
                    session["username"] = username
                    session["role"] = user["role"]
                    return redirect(url_for("dashboard"))

            else:
                # ── SECURE VERSION ────────────────────────────────────
                # 1. Fetch user by username ONLY with a parameterized query.
                #    Never include the password in the SQL WHERE clause.
                user = conn.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (username,),
                ).fetchone()

                # 2. bcrypt.check_password_hash verifies the salted hash safely.
                if user and bcrypt.check_password_hash(user["password"], password):
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

    # ── Encryption Part 3: Decrypt email for display ──────────
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

    # VULNERABLE version - XSS:
    # Saves raw input without sanitization — allows <script>alert("XSS")</script>
    # clean_comment = raw_comment

    # SECURE version - XSS mitigation:
    # bleach.clean() strips dangerous HTML/JS tags before saving to DB.
    # Jinja2 also escapes output by default (no |safe used in dashboard.html).
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
SECURE_MODE = True  # set to False to demo the RBAC vulnerability

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not SECURE_MODE:
                return f(*args, **kwargs)  # vulnerable: no role check at all

            if "username" not in session:
                return redirect(url_for("login"))

            if session.get("role") != role:
                abort(403)  # secure: wrong role triggers our custom 403 handler

            return f(*args, **kwargs)
        return decorated
    return decorator


# ── Custom 403 error handler ──────────────────────────────────
# Without this, Flask shows its default plain-text 403 page instead of our 403.html.
@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


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
