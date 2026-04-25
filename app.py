import sqlite3
from flask import Flask, render_template, request

app = Flask(__name__)

def get_db():
    """Create a SQLite connection and return rows like dictionaries."""
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the users table if it does not exist."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

# Ensure the database table exists when the app starts.
init_db()

@app.route("/register", methods=["GET", "POST"])
def register():
    """Render the registration form and create a user on POST."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = None
        # inside try if the user tryied SQL inject the app won't crash
        try:
                conn = get_db()

                # NOTE: This query is intentionally vulnerable for security practice.
                 # query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                 
                 # NOTE: This query is not vulnerable to SQL Injection 
                query = "SELECT * FROM users WHERE username = ? AND password = ?", (username, password),
                user = conn.execute(query).fetchone()
                conn.close()

                if user:
                    return "Login successful!"
                return "Invalid username or password."
        except sqlite3.Error:
            return "Registration failed due to a database error.", 500
        finally:
            if conn:
                conn.close()

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Render the login form and validate credentials on POST."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = None
        try:
            conn = get_db()
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? AND password = ?",
                (username, password),
            ).fetchone()
            if user:
                return "Login successful!"
            return "Invalid username or password."
        except sqlite3.Error:
            return "Login failed due to a database error.", 500
        finally:
            if conn:
                conn.close()

    return render_template("login.html")

@app.route("/")
def home():
    """Render the home page with navigation links."""
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
