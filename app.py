import sqlite3
import bleach
from flask import Flask, render_template, request, session, redirect, url_for

app = Flask(__name__)
app.secret_key = "temporary-dev-key"


def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
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
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password)
        )
        conn.commit()
        conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        ).fetchone()
        conn.close()

        if user:
            session["username"] = username
            return redirect(url_for("dashboard"))

        return "Invalid username or password."

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    comments = conn.execute("SELECT * FROM comments").fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
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


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
