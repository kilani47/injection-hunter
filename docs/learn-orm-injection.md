# Learning notes: ORM injection

> A from-scratch primer on ORM injection: what an ORM actually is and why
> anyone uses one, what it protects against, the one idea that explains why
> "using an ORM" is not the same claim as "safe from injection," the
> raw-SQL escape hatch every major ORM ships, identifier injection as a
> second, genuinely distinct bug shape parameterization doesn't cover,
> the NoSQL question, and the defenses. Grounded in OWASP's Top Ten
> injection guidance, MITRE's CWE, and the official SQLAlchemy and Django
> documentation (see **References** at the end).

---

## 0. What is an ORM and why does anyone use one?

**ORM** stands for **Object-Relational Mapper**. That's a mouthful. The plain
version: an ORM is a library that acts as a translator between your
programming language and your database, so you can talk to the database in
your language's own terms instead of writing raw SQL strings.

### Without an ORM

Without an ORM, every database interaction involves writing SQL yourself
and handing it to a low-level database driver:

```python
# Plain Python, no ORM
cursor.execute(
    "SELECT id, username, email FROM users WHERE username = %s",
    (username,)
)
row = cursor.fetchone()
if row:
    user_id, user_name, user_email = row
```

This works, but notice what you're doing:

- Typing raw SQL strings, which the database interprets at runtime
- Getting back a raw tuple of values (`row[0]`, `row[1]`, ...) that
  has no labels until you unpack them yourself
- Doing all the query logic (joins, filters, pagination) by writing
  SQL strings by hand, in every file that needs it

### With an ORM

With an ORM (SQLAlchemy, in this example), the same interaction becomes:

```python
# SQLAlchemy ORM
user = db.query(User).filter(User.username == username).first()
if user:
    print(user.id, user.username, user.email)  # named attributes
```

The ORM translates `db.query(User).filter(User.username == username)` into
the SQL string `SELECT ... FROM users WHERE username = ?` automatically, sends
the value safely as a bound parameter, and hands you back a `User` *object*
with `.id`, `.username`, `.email` attributes instead of a raw tuple.

### The architecture — where the ORM sits

```
  YOUR CODE                 ORM LAYER                 DATABASE
  ─────────────────         ─────────────────────     ──────────────────
  User objects &            translates method          receives safe
  method calls    ──────►   calls into SQL     ──────► parameterized SQL
                            handles connections         runs the query
                            maps rows ↔ objects         returns rows
                 ◄──────    hands back objects  ◄──────
  user.username             (User, Post, etc.)
  user.email
```

The ORM is a layer of code that sits between your application and the
database. You never talk to the database directly; you talk to the ORM, and
the ORM talks to the database for you.

### Why do developers use ORMs instead of raw SQL?

There are four concrete reasons most codebases end up with an ORM:

**1. You work in your own language, not SQL.**
Most application code is Python, Java, Ruby, etc. With an ORM, you define a
`User` class with `.username` and `.email` fields, and querying feels like
calling a method on that class. You don't have to context-switch into SQL
every time you need a record.

**2. The ORM handles the tedious parts.**
Database connections, connection pooling, keeping track of which objects
have changed and need to be saved back ("dirty tracking"), generating the
correct SQL dialect for different databases (MySQL vs PostgreSQL vs SQLite)
— the ORM manages all of this. You'd have to write that infrastructure
yourself otherwise.

**3. The ORM's normal query API is automatically safe from SQL injection.**
This is the security angle that matters for these notes. When you write
`filter(User.username == username)`, the ORM sends the SQL structure and the
value `username` to the database as *two separate things*. The value is never
concatenated into the SQL text. An attacker can't "break out" of a quote
that was never there. This is the same mechanism as a correctly-written raw
parameterized query (`cursor.execute("... WHERE id = ?", (x,))`); the ORM's
safe API is a friendlier way to reach that mechanism automatically.

**4. Database portability.**
An ORM query written against SQLite locally can run against PostgreSQL in
production without rewriting the query layer, because the ORM translates
to whatever SQL dialect the connected database speaks.

### The honest downside

ORMs don't cover everything. Complex queries — multi-table reports, custom
aggregations, database-specific functions, sorting by a caller-chosen
column — sometimes can't be expressed through the ORM's object-and-method
API alone. So every serious ORM ships a **raw-SQL escape hatch**: a way to
write plain SQL when you need to. That escape hatch is where ORM injection
lives.

---

## 1. The one idea that makes ORM injection not a new injection type

> **The whole bug class in one sentence:** ORM injection isn't a fourth
> kind of injection alongside SQL/NoSQL/LDAP — it's classic SQL injection,
> reached through a part of the ORM that was never parameterized to begin
> with, usually a raw-query escape hatch the ORM itself ships on purpose.

For its own, normal query-building API, every major ORM keeps values and
query structure separate. This is the exact same mechanism as a
parameterized raw query. There is no quote for an attacker to "break out
of," because the value was never concatenated into the SQL text in the
first place.

Every ORM worth using ships a raw-SQL escape hatch because its safe,
object-oriented API genuinely cannot express every query a real application
eventually needs. SQLAlchemy's is `text()`. Django's are `.raw()`,
`.extra()`, and `RawSQL`. Hibernate's (Java) is a native SQL query.
Sequelize's (Node.js) is `sequelize.query()`. None of these escape hatches
are themselves the bug — each one has its own correct, parameterized way to
accept input. The bug is what happens when a developer reaches for one and
builds its SQL string by hand, with f-strings, `+` concatenation, or
`.format()`, instead of using that escape hatch's own bound-parameter syntax.

```
   SAFE (ORM's own query-building API)
   ┌─────────────────────────────────────────────────┐
   │  .filter(User.username == username)              │
   │  value and query structure: two separate channels│
   │  no string for a quote to break out of           │
   └─────────────────────────────────────────────────┘

   UNSAFE (raw-SQL escape hatch, built by hand)
   ┌─────────────────────────────────────────────────┐
   │  text(f"username = '{username}'")                │
   │  value is now INSIDE the SQL string              │
   │  exactly as injectable as no ORM at all          │
   └─────────────────────────────────────────────────┘
```

OWASP's own Top Ten injection category names ORM injection directly as
one of the ways "hostile data is used within the parameters of a
search query to scrape additional, sensitive records from a database,"
and maps it toward the same injection family as SQL injection, not a
separate one.

---

## 2. How to tell you're dealing with ORM injection at all

This is the one place ORM injection genuinely differs from the other
injection classes in these notes, and it's worth being direct about
it: **from a blackbox tester's perspective, you usually can't tell at
all, and that's fine.** The payload that works against a raw
`cursor.execute()` f-string and the payload that works against an
ORM's `text()` f-string are identical: `' OR '1'='1' -- `, the exact
same classic SQLi probes from the SQL-injection fundamentals already
cover it. The ORM sits upstream of the SQL string, not upstream of the
quote-breakout itself. You don't need a different detection technique,
you need the same one.

Where ORM involvement actually becomes visible is **whitebox** recon,
when source code or a stack trace is available:

- A **framework fingerprint** in error messages or stack traces
  (`sqlalchemy.exc.ProgrammingError`, a `django.db` traceback, a
  Hibernate `org.hibernate.exception.SQLGrammarException`) tells you
  which ORM is in play, and therefore which escape-hatch function
  names are worth grepping the source for.
- Grepping source for the escape-hatch names themselves is the single
  highest-value recon step once source is available: `text(`, `.raw(`,
  `.extra(`, `.from_statement(`, `db.session.execute(`,
  `sequelize.query(`, a native SQL query in Hibernate/JPA. Every one of
  these is a candidate sink, worth checking by hand for string
  formatting feeding directly into it.
- A query that clearly needs dynamic structure the ORM's safe API
  can't express (sorting by a caller-chosen column, a complex
  multi-table report) is a strong prior that a raw escape hatch was
  used somewhere nearby, because that is exactly the situation these
  escape hatches exist for.

The honest takeaway: "this app uses an ORM" is never, by itself, a
reason to rule out injection. It's a reason to go looking specifically
for where that ORM's own safety net was bypassed on purpose.

---

## 3. Pattern A: the raw-SQL escape hatch

Template, the shape every ORM's escape hatch takes once it's built by
hand instead of with bound parameters:

```python
# SQLAlchemy
clause = text(f"username = '{username}' AND password = '{password}'")
matched = db.query(User).filter(clause).first()
```

```python
# Django, the equivalent shape
User.objects.raw(f"SELECT * FROM app_user WHERE username = '{username}'")
```

Both of these execute **exactly** the string handed to them. Whatever
interpolated the request value into that string did so *before* the
database driver, or the ORM's own safe layer, ever had a chance to
treat it as a bound value instead of SQL text. The fix, in both cases,
is the escape hatch's own correct parameter-binding syntax, which
every major ORM provides specifically so this escape hatch doesn't
have to mean "give up parameterization":

```python
# SQLAlchemy, bound parameters inside text()
clause = text("username = :u AND password = :p")
matched = db.query(User).filter(clause).params(u=username, p=password).first()
```

```python
# Django, parameters passed alongside the SQL, never inside it
User.objects.raw("SELECT * FROM app_user WHERE username = %s", [username])
```

### The classic payload still works unmodified

Because the string is assembled exactly the way a raw, no-ORM query
would be, the exact same `' OR '1'='1' -- ` family of payloads from
SQL injection fundamentals works here unchanged. Substituting into the
template above:

```
username = ' OR '1'='1' --
password  = anything
```

builds:

```sql
username = '' OR '1'='1' -- ' AND password = 'anything'
```

MariaDB/MySQL reads `-- ` as a line comment, discarding everything
after it, including the real password check. What actually executes is
a `WHERE` clause matching every row in the table (`'1'='1'` is always
true), and whichever row-ordering the call naturally returns first
(often the lowest primary key with no explicit `ORDER BY`) is what the
calling code treats as "the matched user." This is not a new technique
to learn, it is proof that the technique you already know doesn't care
which layer of code assembled the vulnerable string.

---

## 4. Pattern B: identifier injection through the ORM's own safe API

This is the pattern worth knowing specifically *because* it's easy to
miss even after Pattern A is well understood: **parameterization only
ever protects values, never identifiers** (table names, column names,
`ORDER BY` targets). A bound parameter can stand in for `'alice'`; it
cannot stand in for the bare word `username` used as a column name,
because SQL's own grammar doesn't allow a placeholder in that
position at all. Any code that accepts a caller-chosen identifier and
splices it into a query, even through an otherwise-safe ORM call,
reopens the same string-injection problem in a spot bound parameters
were never designed to reach.

```python
# looks like it's using the ORM's safe API, isn't safe
sort_column = request.args.get("sort", "id")
db.query(User).order_by(text(sort_column)).all()
```

If `sort_column` is meant to be one of a small, known set
(`"username"`, `"created_at"`), nothing here stops it from being
arbitrary SQL instead: `id; DROP TABLE users; --` or a subquery used
purely for its side effects, depending on what the surrounding driver
allows to execute in that position. The fix isn't a bound parameter
(there is no parameter syntax for "this literal column name"), it's an
**allowlist**: validate the caller's choice against a small, explicit
set of permitted column names before it ever reaches the query, and
reject anything else outright.

```python
ALLOWED_SORT_COLUMNS = {"username", "created_at"}
if sort_column not in ALLOWED_SORT_COLUMNS:
    abort(400)
db.query(User).order_by(getattr(User, sort_column)).all()
```

This pattern generalizes past ORMs: table names, column names, and
`ORDER BY`/`GROUP BY` targets are never parameterizable in *any* SQL
API, raw or ORM-wrapped, which is exactly why they're worth checking
for by name, independent of whether the surrounding query otherwise
looks properly bound.

---

## 5. The NoSQL question

**Is there a NoSQL version of ORM injection?**

Short answer: ORM injection, as a named category, refers specifically to
injection through a SQL ORM's escape hatches. The underlying bug is classic
SQL injection. NoSQL injection is a separate category for a different
class of databases entirely.

The longer version:

```
  SQL databases          NoSQL databases
  (MariaDB, PostgreSQL,  (MongoDB, Redis,
  SQLite, Oracle…)       CouchDB, Cassandra…)
        │                       │
        │                       │
   SQLAlchemy,             ODMs (Object-Document
   Django ORM,             Mappers): Mongoengine,
   Hibernate…              Motor, Beanie…
        │                       │
        └──────────┬────────────┘
                   │
         Two different attack classes:
         SQLi / ORM injection    NoSQLi
```

**NoSQL databases** don't use SQL — they have their own query languages and
formats (MongoDB uses JSON-like query documents, for example). **NoSQLi**
(NoSQL injection) is the attack class for those databases. The techniques
are genuinely different: instead of breaking out of a SQL quote character,
you're often injecting operator keys into a JSON query object, or using
MongoDB's `$where` with JavaScript, or exploiting how the application
constructs a query document from user input.

**ODMs** (Object-Document Mappers) are the NoSQL equivalent of ORMs —
they let you work with MongoDB documents as Python objects, for example.
An ODM has the same "safe API vs escape hatch" dynamic, and **ODM
injection is a real thing** — but its shape is fundamentally different
from ORM injection, because the underlying attack is not SQL injection.

### How ODM injection actually works

MongoDB queries are JSON-like documents, not strings. So "injection"
means inserting MongoDB **query operators** into the document, not
breaking out of a quote character. An operator like `$gt` (greater
than) or `$ne` (not equal) is a key inside the query object — if the
application passes user-supplied input directly into that query document
without validating that the value is the right type (a string, not an
object), the user can supply an operator instead:

```
Attacker sends:   {"username": {"$ne": null}, "password": {"$ne": null}}

MongoDB runs:     db.users.findOne({username: {$ne: null}, password: {$ne: null}})

Result:           matches the first user in the collection regardless
                  of what their actual username or password is
```

There is no string to break, no quote to escape — the injection is
entirely about shape: the application expected a scalar (a string), the
attacker supplied an object, and the database interpreted the object's
keys as query operators.

**The safe API vs escape hatch structure is the same:**

```python
# Mongoengine (Python ODM for MongoDB)

# SAFE — Mongoengine builds the query document, enforces types
user = User.objects(username=username, password=password).first()

# UNSAFE — raw query document built from user input directly
user = User.objects(__raw__={
    "username": request.json["username"],  # could be {"$ne": null}
    "password": request.json["password"],
}).first()
```

```javascript
// Mongoose (Node.js ODM for MongoDB)

// SAFE — if the app validates that username is a string before this
const user = await User.findOne({ username: username });

// UNSAFE — body parsed as JSON, no type check; {"$ne": null} arrives
// as an object and Mongoose passes it straight to MongoDB as an operator
const user = await User.findOne({ username: req.body.username });
```

**The `$where` escalation.** MongoDB's `$where` operator accepts a
JavaScript string and evaluates it inside the database engine. If an
ODM escape hatch or raw driver call allows `$where` with a
user-supplied value, the attacker can run arbitrary JavaScript in the
query context — far beyond a simple authentication bypass.

**The fix for ODM injection** is the same conceptual fix as for ORM
injection, translated to the NoSQL world: use the ODM's own typed API
(which enforces that field values are the right type), validate and
cast user input to the expected scalar type before it touches any
query, and never pass a raw user-supplied object directly into a query
document.

**What's not related to ORM injection:** the target database doesn't
speak SQL, there is no string to splice, and the payloads are entirely
different. The structural parallel (safe library API bypassed by an
escape hatch or raw pass-through) is real, but the techniques,
payloads, and defenses are different enough that NoSQLi — including
ODM injection — is covered as its own topic (see the Phase 4 notes),
not a variation of ORM injection.

**What's true of both:** "this app uses an ORM/ODM" is never, by
itself, a reason to rule out injection. Both attack classes exploit
the moment when a developer bypasses the library's safe path and
builds a query structure by hand from user input.

---

## 6. A related, genuinely different bug: mass assignment

This is not injection, and it's worth being precise about the
distinction, but it shows up constantly in the same "ORM security"
conversations and is easy to confuse with Pattern A. **Mass assignment**
(also called over-posting) happens when application code takes an
entire request body and hands it directly to an ORM model's
constructor or update call, trusting that only the fields the UI meant
to expose will ever be present:

```python
# looks convenient, trusts every key the caller sent
new_user = User(**request.json)
db.session.add(new_user)
```

If `User` has an `is_admin` column the UI never shows a form field
for, nothing here stops a caller from simply including
`"is_admin": true` in their request body anyway, the ORM happily
assigns it, because from the model's perspective a request-supplied
dict and a legitimately-constructed one look identical. No SQL string
was ever broken; the query the ORM eventually runs is perfectly
well-formed and fully parameterized. The bug is upstream of any query
at all: it's trusting attacker-controlled data to pick *which fields*
get written, not just *what values* go into fields the application
already decided to accept.

The fix is an allowlist again, this time of fields rather than
columns: construct the model from an explicit, named set of expected
request keys, never from the raw request body itself.

```python
new_user = User(username=request.json["username"], email=request.json["email"])
```

---

## 7. Defense (the actual fix)

- **Never build a raw-SQL string by hand and hand it to an ORM's raw
  escape hatch.** Use that escape hatch's own bound-parameter syntax
  every time (`text("... :x").params(x=value)` in SQLAlchemy,
  `.raw(sql, [params])` in Django, the equivalent in any other ORM).
  If the query doesn't genuinely need the escape hatch, prefer the
  ORM's own safe query-building API instead.
- **Treat every raw-SQL escape hatch as a SQL-injection sink**, and
  review it exactly like a raw `cursor.execute()` call. "It's behind
  an ORM" is never a mitigating factor by itself, it only matters once
  you've confirmed the specific call in question actually went
  through the ORM's parameterized path.
- **Allowlist identifiers, never parameterize them.** Table names,
  column names, and sort/group targets need an explicit set of
  permitted values checked in application code before they ever reach
  a query, bound parameters cannot cover this position in SQL's
  grammar.
- **Allowlist fields on mass-assignable constructors.** Build models
  from an explicit, named set of expected keys, never from an entire
  unfiltered request body.
- **Least-privilege database account.** The same mitigation every
  injection class in these notes shares: a database account scoped to
  only the grants an application's features actually need limits how
  far any one injection bug, ORM-mediated or not, can reach.

---

## 8. References (official / primary)

- **OWASP Top Ten 2021, A03 Injection:** https://owasp.org/Top10/A03_2021-Injection/
  (names ORM injection directly as a form of injection where "hostile
  data is used within the parameters of a search query... to extract
  additional, sensitive records")
- **MITRE CWE-564, SQL Injection: Hibernate:** https://cwe.mitre.org/data/definitions/564.html
  (the CWE entry OWASP's own 2021 Top Ten injection category maps
  ORM-mediated SQL injection to)
- **SQLAlchemy Unified Tutorial, Sending Parameters:**
  https://docs.sqlalchemy.org/en/20/tutorial/dbapi_transactions.html
  ("a Python literal value should never be stringified into SQL
  string directly"; demonstrates the `text("... :y")` bound-parameter
  pattern)
- **Django Security docs, SQL injection protection:**
  https://docs.djangoproject.com/en/stable/topics/security/
  (Django querysets are protected via parameterization by construction;
  raw/custom SQL "should be used sparingly" with parameters escaped
  via the driver, never interpolated)
- **Django, Performing raw SQL queries:**
  https://docs.djangoproject.com/en/stable/topics/db/sql/
  (the `.raw()`/`.extra()` parameter-passing syntax referenced above)
