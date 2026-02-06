from flask import Flask, render_template, request, redirect, session
import sqlite3
import hashlib
import re

app = Flask(__name__)
app.secret_key = "project_secret_key"

# -------- DATABASE SETUP --------
def get_db():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT,
        password TEXT
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS reports(
        url TEXT,
        risk INT
    )""")

    conn.commit()
    return conn

# -------- SECURITY UTILITIES --------
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

def calculate_risk(url):
    risk = 0

    if "@" in url:
        risk += 25
    if url.startswith("http://"):
        risk += 20
    if len(url) > 40:
        risk += 15
    if re.search("login|verify|bank|secure|update|account", url.lower()):
        risk += 30
    if "-" in url:
        risk += 10

    return min(risk, 100)

# -------- ROUTES --------
@app.route("/")
def home():
    return render_template("login.html")

@app.route("/register", methods=["POST"])
def register():
    u = request.form["username"]
    p = hash_password(request.form["password"])

    db = get_db()
    cur = db.cursor()

    cur.execute("INSERT INTO users VALUES (?,?)", (u, p))
    db.commit()

    return "Registered Successfully! Go back and Login."

@app.route("/login", methods=["POST"])
def login():
    u = request.form["username"]
    p = hash_password(request.form["password"])

    db = get_db()
    cur = db.cursor()

    user = cur.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (u, p)
    ).fetchone()

    if user:
        session["user"] = u
        return redirect("/dashboard")
    return "Invalid Credentials"

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user" not in session:
        return redirect("/")

    result = None

    if request.method == "POST":
        url = request.form["url"]
        risk = calculate_risk(url)

        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO reports VALUES (?,?)", (url, risk))
        db.commit()

        result = risk

    return render_template("dashboard.html", result=result)

app.run(debug=True)
