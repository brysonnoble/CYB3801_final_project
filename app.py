"""
CYB3801 Final Project - Vulnerable vs. Mitigated web application.

Team: Bryson Noble, Katherine Kennedy, Neva Ildem

Each team member demonstrates one web vulnerability and its mitigation:
  - Bryson Noble   : Sensitive data in localStorage/cookies -> XSS theft.
                     Mitigated by storing data server-side in SQLite with an
                     httpOnly session cookie.  (IMPLEMENTED BELOW)
  - Katherine Kennedy : Insecure Direct Object Reference (IDOR).   [TODO]
  - Neva Ildem        : SQL Injection.                             [TODO]

Teammates: add your routes in the clearly marked sections at the bottom.
"""

import os
import sqlite3
import secrets
import re

from flask import (
    Flask,
    request,
    redirect,
    make_response,
    jsonify,
    render_template,
)

# ---------------------------------------------------------------------------
# Configuration (driven by the container's environment variables)
# ---------------------------------------------------------------------------
HOST = os.environ.get("BURPLAB_HOST", "127.0.0.1")
PORT = int(os.environ.get("BURPLAB_PORT", "5000"))
STATE_DIR = os.environ.get("BURPLAB_STATE", os.path.join(os.path.dirname(__file__), "state"))

os.makedirs(STATE_DIR, exist_ok=True)
DB_PATH = os.path.join(STATE_DIR, "app.db")

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Database helpers (shared SQLite file in the writable state directory)
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables and seed a couple of demo accounts."""
    conn = get_db()
    cur = conn.cursor()
    # Demo users with "sensitive" information the vulnerability targets.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email    TEXT NOT NULL,
            ssn      TEXT NOT NULL,
            balance  TEXT NOT NULL
        )
        """
    )
    # Server-side sessions used by the MITIGATED version.  The sensitive data
    # never leaves the server; the browser only gets an opaque session id in an
    # httpOnly cookie.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            sid      TEXT PRIMARY KEY,
            user_id  INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    # Stored comments feed used to demonstrate the stored-XSS sink.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS comments (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            body TEXT NOT NULL
        )
        """
    )
    seed = [
        ("alice", "password123", "alice@example.com", "123-45-6789", "$12,430.55"),
        ("bob", "hunter2", "bob@example.com", "987-65-4321", "$2,110.08"),
    ]
    for username, password, email, ssn, balance in seed:
        cur.execute(
            "INSERT OR IGNORE INTO users (username, password, email, ssn, balance) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, password, email, ssn, balance),
        )
    conn.commit()
    conn.close()


def find_user(username, password):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    conn.close()
    return row


# ---------------------------------------------------------------------------
# Landing page
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ===========================================================================
# BRYSON NOBLE
# Vulnerability: sensitive data stored client-side in localStorage + a
#                JavaScript-readable cookie, exposed to theft via XSS.
# Mitigation:    store the data server-side in SQLite, hand the browser only
#                an opaque httpOnly session id, and escape user input.
# ===========================================================================

# --- Vulnerable demo --------------------------------------------------------
@app.route("/bryson/vulnerable", methods=["GET", "POST"])
def bryson_vulnerable():
    """
    On login the server returns the full sensitive profile as JSON.  The page's
    JavaScript then stashes it in localStorage and a readable cookie, so any
    script running on the page (e.g. an XSS payload) can read it back.
    """
    if request.method == "POST":
        user = find_user(request.form.get("username", ""), request.form.get("password", ""))
        if not user:
            return jsonify({"error": "invalid credentials"}), 401
        # The whole sensitive record is shipped to the browser.
        return jsonify(
            {
                "username": user["username"],
                "email": user["email"],
                "ssn": user["ssn"],
                "balance": user["balance"],
                "token": secrets.token_hex(16),
            }
        )
    comments = get_comments()
    # NOTE: comments are intentionally rendered WITHOUT escaping to provide a
    # stored-XSS sink that can read the client-side sensitive data.
    return render_template("bryson_vulnerable.html", comments=comments)


@app.route("/bryson/steal")
def bryson_steal():
    """Attacker's collection endpoint - proves the XSS exfiltration works."""
    stolen = request.args.get("d", "")
    print(f"[BRYSON][XSS EXFIL] attacker received: {stolen}")
    return ("", 204)


# --- Mitigated demo ---------------------------------------------------------
@app.route("/bryson/mitigated", methods=["GET", "POST"])
def bryson_mitigated():
    """
    On login the sensitive data stays in SQLite.  The browser only receives an
    opaque session id in an httpOnly + SameSite cookie, which JavaScript cannot
    read, so XSS has nothing sensitive to steal.
    """
    if request.method == "POST":
        user = find_user(request.form.get("username", ""), request.form.get("password", ""))
        if not user:
            resp = make_response(redirect("/bryson/mitigated?error=1"))
            return resp
        sid = secrets.token_urlsafe(32)
        conn = get_db()
        conn.execute("INSERT INTO sessions (sid, user_id) VALUES (?, ?)", (sid, user["id"]))
        conn.commit()
        conn.close()
        resp = make_response(redirect("/bryson/mitigated"))
        # httpOnly: not readable from document.cookie; SameSite=Strict: not sent
        # cross-site.  No sensitive data is placed client-side at all.
        resp.set_cookie("sid", sid, httponly=True, samesite="Strict")
        return resp

    user = current_user()
    comments = get_comments()
    return render_template(
        "bryson_mitigated.html",
        user=user,
        comments=comments,
        error=request.args.get("error"),
    )


@app.route("/bryson/mitigated/profile")
def bryson_profile():
    """Sensitive data is only returned after validating the server-side session."""
    user = current_user()
    if not user:
        return jsonify({"error": "not authenticated"}), 401
    return jsonify(
        {
            "username": user["username"],
            "email": user["email"],
            "ssn": user["ssn"],
            "balance": user["balance"],
        }
    )


@app.route("/bryson/logout")
def bryson_logout():
    sid = request.cookies.get("sid")
    if sid:
        conn = get_db()
        conn.execute("DELETE FROM sessions WHERE sid = ?", (sid,))
        conn.commit()
        conn.close()
    resp = make_response(redirect("/bryson/mitigated"))
    resp.delete_cookie("sid")
    return resp


def current_user():
    """Look up the logged-in user from the server-side session cookie."""
    sid = request.cookies.get("sid")
    if not sid:
        return None
    conn = get_db()
    row = conn.execute(
        "SELECT u.* FROM users u JOIN sessions s ON s.user_id = u.id WHERE s.sid = ?",
        (sid,),
    ).fetchone()
    conn.close()
    return row


# --- Shared comments helpers (used by both Bryson demos) --------------------
@app.route("/bryson/comment", methods=["POST"])
def bryson_comment():
    body = request.form.get("body", "").strip()
    if body:
        conn = get_db()
        conn.execute("INSERT INTO comments (body) VALUES (?)", (body,))
        conn.commit()
        conn.close()
    # Send the user back to whichever demo they posted from.
    return redirect(request.form.get("next", "/bryson/vulnerable"))


def get_comments():
    conn = get_db()
    rows = conn.execute("SELECT body FROM comments ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    return [r["body"] for r in rows]


# ===========================================================================
# KATHERINE KENNEDY  -  Insecure Direct Object Reference (IDOR)
# TODO: add your vulnerable + mitigated routes here.
# ===========================================================================


# ===========================================================================
# NEVA ILDEM  -  SQL Injection
# ===========================================================================
# --- Neva's SQL injection: vulnerable + mitigated login --------------------
NEVA_RESULT_COLS = ["username", "email", "ssn", "balance"]
NEVA_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")


def _rows_to_dicts(rows):
    return [{col: row[col] for col in NEVA_RESULT_COLS} for row in rows]


@app.route("/neva/vulnerable", methods=["GET", "POST"])
def neva_vulnerable():
    """VULNERABLE login: user input is concatenated into the SQL string."""
    result = None
    executed_query = None
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        query = (
            "SELECT username, email, ssn, balance FROM users "
            "WHERE username = '" + username + "' AND password = '" + password + "'"
        )
        executed_query = query
        print(f"[NEVA][SQLi] executing: {query}")
        conn = get_db()
        try:
            rows = conn.execute(query).fetchall()
            result = _rows_to_dicts(rows)
        except Exception as exc:
            error = str(exc)
        finally:
            conn.close()
    return render_template(
        "neva_vulnerable.html",
        result=result,
        executed_query=executed_query,
        error=error,
        cols=NEVA_RESULT_COLS,
    )


@app.route("/neva/mitigated", methods=["GET", "POST"])
def neva_mitigated():
    """MITIGATED login: input validation + parameterized query (find_user)."""
    result = None
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if not NEVA_USERNAME_RE.match(username):
            error = "Username must be 1-32 letters, numbers, or underscores."
        else:
            user = find_user(username, password)
            if user:
                result = [{col: user[col] for col in NEVA_RESULT_COLS}]
            else:
                error = "Invalid credentials."
    return render_template(
        "neva_mitigated.html",
        result=result,
        error=error,
        cols=NEVA_RESULT_COLS,
    )


if __name__ == "__main__":
    init_db()
    app.run(host=HOST, port=PORT)
