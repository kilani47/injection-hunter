# Learning notes: SQL injection

> A from-scratch primer on SQL injection: the one idea behind every
> variant, how to confirm it exists at all, the full in-band/blind/
> out-of-band taxonomy (error-based, UNION-based, boolean-blind,
> time-based, out-of-band, second-order), and the one real fix. Grounded
> in PortSwigger's own SQLi methodology, MITRE's CWE, and MariaDB's
> official function reference (see **References** at the end).

---

## 1. The one idea that makes SQL injection work

A SQL query is normally built from two things that are supposed to stay
separate: the query's fixed *structure* (written by the developer) and
the *data* a user supplies (a username, a search term). When an
application builds that query by concatenating request data directly
into the SQL text, the database can no longer tell the difference
between "a value" and "more query": anything the request contains that
has meaning in SQL's own grammar, most importantly a quote character
closing the literal it was supposed to sit inside, stops being data and
starts being query structure the attacker now controls.

```python
# vulnerable: user input becomes part of the SQL text itself
query = f"SELECT * FROM users WHERE username = '{username}'"
```

```
username = alice               -> SELECT * FROM users WHERE username = 'alice'
                                    ordinary, safe, no special characters

username = ' OR '1'='1' -- 
                                -> SELECT * FROM users WHERE username = '' OR '1'='1' -- '
                                    the quote closed the literal early;
                                    everything after is new query logic
```

> **The whole bug class in one sentence:** SQL injection happens
> whenever request data reaches a SQL string without being kept in a
> separate channel from the query's own structure, and every technique
> below is just a different way of using that gap, to bypass a check,
> to read data back directly, or, when nothing comes back at all, to
> infer data one bit at a time through some side channel instead.

The fix for the bug class, in one line, before any of the techniques
below: a **parameterized query** (also called a prepared statement)
sends the query structure and the data as two genuinely separate
things to the database driver, so there is no string for a quote to
break out of, because the value was never concatenated into query text
in the first place.

```python
# safe: structure and data travel to the driver separately
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

---

## 2. How to tell you're dealing with SQL injection at all

The standard first probe is a single quote, sent alone, into any input
that might reach a query:

```
value = '
```

Three distinct outcomes are all meaningful:

- **A database error comes back**, often containing the DBMS's own
  product name and a syntax-error message. This is the strongest
  positive signal, and it doubles as free DBMS fingerprinting: a MySQL/
  MariaDB error reads differently from a PostgreSQL error, which reads
  differently from an Oracle `ORA-` prefix, often enough on its own to
  tell you which error-based or time-based functions (§4, §6) are even
  available to try next.
- **The page's behavior visibly changes** (a result set disappears, a
  login that should fail now succeeds) with no visible error at all.
  This is the entry point for the blind techniques, §5-§6, the query is
  still breaking, the application just isn't showing you the proof
  directly.
- **Nothing changes whatsoever.** Either the input never reaches a
  query, or it's being handled safely (parameterized, or at minimum
  escaped). Try a quote-free structural probe next, `' OR '1'='1` has a
  quote on each end and no visible syntax break if it's working, so a
  single lone quote failing doesn't rule out injection by itself,
  always confirm with more than one probe shape before concluding a
  given input is clean.

---

## 3. In-band, blind, and out-of-band: the shape of the rest of this doc

Every technique below is one of three fundamentally different ways to
get an answer back out of the database, and which one applies is
decided entirely by what the application does with the query's result,
not by anything about the query itself:

```
IN-BAND      the query's own result (or its own error message)
             comes back directly in the application's response
             -> Pattern A (error-based), Pattern B (UNION-based)

BLIND        the response never shows data or errors, only a
             true/false difference, or a timing difference
             -> Pattern C (boolean-blind), Pattern D (time-based)

OUT-OF-BAND  the response shows nothing useful at all, not even
             a true/false signal, so the database itself is made
             to carry data out through a completely separate channel
             -> Pattern E
```

---

## 4. Pattern A: Error-based

If the application reflects the database's own error text back in its
response, a deliberately malformed query can be used to force the
error message itself to carry real data, not just confirm that an
error occurred. MariaDB/MySQL's `EXTRACTVALUE()` function (officially
documented as taking an XML fragment and an XPath expression, returning
the matching text node's content) raises a genuine, specific error,
`XPATH syntax error`, whenever the XPath argument it's given is
malformed:

```sql
EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))
```

`0x7e` is the `~` character, not valid at the start of a real XPath
expression, so this always raises an XPath-syntax error, and because
the error text includes the malformed expression itself, whatever the
subquery evaluated to (here, the database's version string) comes back
embedded directly in the error message, one request, no blind walking
required. This is the same fundamental idea as the NoSQL notes' Pattern
C (`$convert` conversion-failure error leak) and the XML notes' tag
injection, a verbose error channel that was only ever meant to help
debugging gets repurposed to carry real data.

---

## 5. Pattern B: UNION-based

`UNION` combines the result rows of two separate `SELECT` statements
into one result set. If an application's query result is reflected
back in the response (a search results page, a listing), an injected
`UNION SELECT` can append arbitrary rows, including rows pulled from a
completely different table, directly into that visible output.

Two structural requirements have to be satisfied first, both
discoverable through the application's own error behavior before the
real payload is ever sent:

```
1. column count must match
   ' ORDER BY 1-- , ' ORDER BY 2-- , ... increment until an error
     appears ("Unknown column") -> one less than that is the real count

2. column types must be compatible
   ' UNION SELECT NULL,NULL,NULL-- , replacing NULLs one at a time
     with a real string value until no type-mismatch error appears
     -> that position accepts text, usable for exfiltrating data
```

Once both are known, the injected `SELECT` can pull from any table the
database account can read, not just the one the original query
targeted:

```sql
' UNION SELECT username, password FROM users-- 
```

---

## 6. Pattern C: Boolean-based blind

When the response carries no error text and no visible query result,
but *does* visibly differ depending on whether an injected condition
is true or false (a "found" vs. "not found" message, a redirect vs. a
login form reload), that true/false difference alone is a working
oracle. Confirming it needs nothing more than a condition that's always
true and one that's always false:

```
' AND '1'='1    -> true  (page behaves as if the query matched)
' AND '1'='2    -> false (page behaves as if the query matched nothing)
```

Once the oracle is confirmed, the same true/false channel walks an
unknown value out one character at a time, asking a yes/no question
about each position:

```
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a    -> true/false?
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='b    -> true/false?
...
```

A binary search over the character set (test `>'m'` before testing
individual letters) turns this from roughly 95 requests per character
into roughly 7, the exact same bisection discipline used in these
notes' NoSQL and LDAP blind-extraction patterns.

---

## 7. Pattern D: Time-based blind

When even the true/false behavioral difference Pattern C relies on
isn't visible (the response looks identical either way), a delay
function conditionally executed is the last resort: the response
itself carries no signal at all, only how *long* it took to arrive
does.

```sql
' OR IF(1=1, SLEEP(5), 0)-- 
```

`SLEEP(5)` only executes, and the response only measurably delays, when
the condition wrapping it evaluates true. A fast response means false,
a ~5-second response means true, and the same bisection walk from
Pattern C applies identically, just measured against a clock instead of
a response body. Confirm the oracle itself first, exactly the same
discipline as every blind technique in these notes: send a
hardcoded-true delay and a hardcoded-false no-delay side by side before
trusting any result built on top of it, a single slow response proves
nothing on its own, a timing difference between a true and a false
version of the *same* payload does.

---

## 8. Pattern E: Out-of-band (OOB)

Sometimes neither an in-band result nor any blind signal, true/false or
timing, ever reaches the response at all, the application might run
the query asynchronously, swallow every outcome identically, or simply
never surface any difference whatsoever. Out-of-band SQL injection
sidesteps the response entirely: instead of reading an answer back
through the HTTP response, the database itself is made to originate a
*separate*, independent network connection, to a host the tester
controls, carrying the data as part of that connection.

```
      query result  ──X──>  HTTP response        (blocked / never shows up)
      query result  ──────>  separate DNS/HTTP lookup  ──────>  attacker's own listener
```

PortSwigger's own methodology describes this as "extremely powerful,"
useful specifically because it works in situations where every other
technique in this document fails to produce any usable signal at all.
The concrete mechanism varies by database engine, common approaches
fold exfiltrated data into a DNS lookup's subdomain, or use a built-in
or custom function capable of making a real outbound HTTP request from
inside the database engine's own process, the data never needs to pass
back through the vulnerable application's response at all, it travels
out through a completely independent channel the application was never
built to carry.

---

## 9. Second-order (stored) SQL injection

Every pattern above assumes the injected string reaches a query in the
same request that submitted it. Second-order injection breaks that
assumption: a value is accepted and stored *safely*, properly
parameterized, escaped correctly, nothing wrong with the write at all,
but is later read back out of storage and concatenated, unsafely, into
a *different* query, somewhere else in the application, in a request
the original attacker may never even see.

```
request 1 (write):  username = "admin'-- "
                     stored safely, parameterized, no bug here at all

... later, a completely different code path ...

request 2 (read):    an admin report builds a query by concatenating
                      the now-stored username value directly into SQL
                      text, with no parameterization this time
                      -> the injection fires here, not at write time
```

This is genuinely harder to find than every pattern above it, because
testing the write path alone, the obvious place to look, finds nothing:
that path is clean. The vulnerability only exists at whichever *later*
read path eventually treats the stored value as trusted, which can be
an entirely different route, an entirely different feature, reviewed by
an entirely different part of an audit. Any value under an attacker's
control that gets stored anywhere and might plausibly be reused in a
later query (usernames, display names, anything echoed into an internal
report or admin view) is worth testing for this specifically, not just
at the point it's first written.

---

## 10. Defense (the actual fix)

- **Parameterized queries / prepared statements, always, for every
  value.** This is the one fix that actually closes the bug class,
  everything else in this section is defense-in-depth around it, not a
  substitute for it.
- **Never return raw database error text in an HTTP response, to any
  audience.** Log the real exception server-side; return a generic
  failure to the caller. This closes Pattern A specifically without
  needing anything else to go right.
- **Allowlist identifiers (table names, column names, `ORDER BY`
  targets) separately from parameterizing values.** A bound parameter
  can stand in for a literal value; it cannot stand in for a bare
  identifier, that position in SQL's own grammar has no parameter
  syntax at all, the same nuance covered in these notes' ORM injection
  document.
- **Re-check every stored value at its later read paths, not just its
  write path.** Second-order injection specifically defeats "we
  validated the input when it came in" as a complete defense, because
  the bug lives downstream of validation, not at it.
- **Least-privilege database account.** A database account scoped to
  only the grants an application's features actually need limits how
  far any injection that does slip through can reach, `UNION`-based
  exfiltration in particular depends entirely on what tables the
  application's own account is allowed to read.

---

## 11. References (official / primary)

- **PortSwigger Web Security Academy, SQL injection:**
  https://portswigger.net/web-security/sql-injection
  (the in-band/blind/out-of-band taxonomy this doc follows: UNION
  attacks, conditional errors, boolean-blind, time-based blind, and
  out-of-band/OAST techniques)
- **MITRE CWE-89, Improper Neutralization of Special Elements used in
  an SQL Command:** https://cwe.mitre.org/data/definitions/89.html
  (official definition; mapped to every OWASP Top Ten injection
  category from 2004 through 2025)
- **MariaDB Knowledge Base, EXTRACTVALUE():**
  https://mariadb.com/kb/en/extractvalue/
  (the function's real signature and its documented `XPATH syntax
  error` behavior on a malformed expression, the mechanism Pattern A's
  error-based leak is built on)
- **OWASP Testing Guide, Testing for SQL Injection** (WSTG-INPV-05):
  https://owasp.org/www-project-web-security-testing-guide/
- **OWASP Cheat Sheet, SQL Injection Prevention:**
  https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
