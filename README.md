# Secure Web App – CSC429 Project

This project is a simple Flask web application developed for the CSC security project. It demonstrates some common web vulnerabilities and the techniques used to mitigate them.

---

## Main Features

- Register a new account
- Login with your credentials
- View a dashboard with your info and a comment section
- Admin page that only admins can access

---

## How to run it

```bash
cd Desktop/Secure-Web-Application
pip install -r requirement.txt
python app.py
```

Then open your browser and go to `https://127.0.0.1:5000`

> The browser will give you a warning about the connection — just click Advanced then Proceed. This is normal because we're using a self-signed certificate locally.

---

## File structure

```
Sec/
├── app.py
├── requirement.txt
├── fernet.key        ← auto-generated
├── users.db          ← auto-generated
├── static/
│   └── css/
│       └── style.css
└── templates/
    ├── index.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── admin.html
    └── 403.html
```

---

## Testing the vulnerabilities

### SQL Injection
In `app.py` set `SQL_INJECTION_MODE = True`, then in the login page try:
- Username: `' OR '1'='1'--`
- Password: anything

The vulnerable version allows login without valid credentials.

### XSS
While logged in, post this as a comment:
```
<script>alert("XSS")</script>
```
In secure mode the text just shows up literally, no popup.

### Access Control
Log in as a regular user and go to `/admin` — you should get a 403 page. Set `SECURE_MODE = False` in `app.py` and you can access it without being admin.

To make a user admin manually:
```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('users.db')
conn.execute(\"UPDATE users SET role='admin' WHERE username='your_username'\")
conn.commit()
"
```

### Password hashing
After registering, run this to check the database:
```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('users.db')
for r in conn.execute('SELECT username, password FROM users').fetchall():
    print(r[0], r[1])
"
```
The password should look like `$2b$...` which is a bcrypt hash, not plaintext.

### Email encryption
To verify email encryption, check the database using:
```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('users.db')
for r in conn.execute('SELECT username, email FROM users').fetchall():
    print(r[0], r[1])
"
```
The email should be encrypted (long random-looking string), not readable.

### HTTPS
The app runs on `https://` using a self-signed cert — you can see it in the URL bar.

---

## Libraries used

- **Flask** – the web framework
- **Flask-Bcrypt** – for hashing passwords
- **cryptography** – for encrypting emails with Fernet
- **bleach** – for sanitizing comments (XSS fix)
- **pyOpenSSL** – to enable HTTPS locally

## Challenges Faced

During the development of the project, several challenges were encountered:

- Maintaining a persistent Fernet encryption key across server restarts. This was solved by storing the generated key inside `fernet.key` instead of generating a new key every time the application runs.

- Demonstrating both vulnerable and secure implementations in the same application without breaking functionality. This was solved using flags such as `SQL_INJECTION_MODE` and `SECURE_MODE`.

- Running HTTPS locally using a self-signed certificate caused browser security warnings. This issue was expected and users can proceed manually for testing purposes.
