# Gate of Trust, Debrief

**Node:** `p1_1` &middot; **Flag:** `SEIYAKU{the_vow_was_never_sealed}` &middot; **Route:** `POST /p1/gate` &middot; **Sink:** `challenges/phase1.py`, `mariadb` (`applicants` table)

## Root cause

The login route builds its SQL query by dropping the raw form fields
straight into an f-string:

```python
# challenges/phase1.py
q = f"SELECT * FROM applicants WHERE username='{u}' AND password='{p}'"  # VULN: string concat
cur.execute(q)
row = cur.fetchone()
```

`u` and `p` come directly from `request.form`, nothing escapes the single
quotes that delimit the string literals in the query. Whatever the
applicant types for `username` is trusted to *stay* a value; MariaDB has no
way to know the difference between "the value is a single quote" and "the
value ends here and new SQL begins."

If any row comes back, the route treats it as a successful login and
renders the row (including its `secret` column) into the admin panel,
there's no check that the row's username is actually `"admin"`, or that the
password comparison was the thing that let it through.

## The walk

**1. Fingerprint with a bare quote.** The very first probe on any login
form that might be building SQL by hand is a single unescaped quote in one
field:

```
username: admin'
password: x
```

The gate doesn't fail quietly, it echoes the raw exception text back to
the page (a second, independent bug: verbose DB errors on a public form).
Against this seed, that comes back as:

```
(1064, "You have an error in your SQL syntax; check the manual that
corresponds to your MariaDB server version for the right syntax to use
near 'x'' at line 1")
```

The phrase *"corresponds to your MariaDB server version"* is MariaDB's own
wording (MySQL's classic 1064 error uses near-identical phrasing, but the
"MariaDB server version" substring is the fingerprint here), one
character told you the exact engine and version family before you've
written a single real payload.

**2. Confirm it's actually reachable, string-context.** Since the error
fired on `username`, the injection point takes string-quoted input, not a
bare integer, so any payload needs to open and close its own `'...'`
context (as opposed to, say, a numeric ID field where you'd inject without
quotes at all: `id=1 OR 1=1`). Probing both fields independently (quote in
`username` alone, then in `password` alone) confirms which parameter(s)
reach the query, here, both do, since both are concatenated into the same
statement.

**3. Break the vow.** Close the `username` string early, then OR in a
condition that's always true, then comment out the rest of the original
query (the trailing `password='...'` clause and its closing quote) so it
never has to match:

```
username: ' OR '1'='1' --
password: whatever
```

The query MariaDB actually executes:

```sql
SELECT * FROM applicants WHERE username='' OR '1'='1' -- ' AND password='whatever'
```

`-- ` (double-dash, then a space, MariaDB requires the trailing whitespace
or comment-of-line-end for this comment style to parse) turns everything
after it into a comment, so the real password check never runs. `'1'='1'`
is unconditionally true, so the `WHERE` clause matches every row in
`applicants`. `fetchone()` returns the first one, row `id=1`, the admin,
regardless of what `password` was submitted.

The gate opens. The admin panel renders the `secret` column of that first
row: the flag.

## HxH analogy

A Nen vow only enforces exactly what it was *worded* to enforce, never
what its caster *meant*. A restriction like "I will only use this ability
on someone who has agreed to a duel with me" sounds airtight until someone
realizes "agreed" was never defined precisely enough: get them to nod at
an unrelated question, and the vow's own logic now reads the condition as
satisfied. The power doesn't malfunction, it does exactly what the words
say, and the words had a hole in them the caster never noticed because
they never tried to argue with their own vow.

The Gate of Trust's vow was *"a name and a password, checked together,
decide who passes."* Nobody specified that a name couldn't also carry
new instructions for how the checking itself works. `' OR '1'='1' --`
doesn't break the gate's logic, it completes it, exactly as literally
worded, with a name that argues its way past the very check meant to stop
it.

## Remediation

- **Parameterized queries, always.** Let the driver, not string
  concatenation, separate code from data:

  ```python
  cur.execute(
      "SELECT * FROM applicants WHERE username=%s AND password=%s",
      (u, p),
  )
  ```

  `%s` here is PyMySQL's placeholder syntax (not Python string
  formatting), the driver sends the query text and the values as
  separate protocol messages, so MariaDB never re-parses user input as
  SQL grammar no matter what characters it contains.
- **Hash passwords**, never store or compare them in plaintext (this seed
  stores plaintext for the lab's own clarity, never do this in anything
  real).
- **Don't return raw DBMS exception text to the client.** Log it
  server-side; show the user a generic "invalid credentials" / "something
  went wrong" message. The verbose error above is what turned a five-minute
  probe into an instant engine fingerprint.
- **Least privilege on the DB account** the app connects with, even with
  parameterization elsewhere, an app account that can only `SELECT` from
  the tables it needs limits the blast radius of the *next* bug, not this
  one.
