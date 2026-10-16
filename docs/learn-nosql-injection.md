# Learning notes: NoSQL injection (MongoDB)

> A from-scratch primer on NoSQL injection against MongoDB: the mental
> model, the operators, all four core attack patterns PortSwigger's own
> NoSQLi methodology names (operator injection, error-based, boolean-blind,
> and time-based), and the defenses. Grounded in MongoDB's own
> operator/aggregation docs and the OWASP Testing Guide (see
> **References** at the end).

---

## 1. The one idea that makes NoSQL injection different

Classic SQL injection is a **syntax break**. The query is a *string*, your
input lands inside a quoted literal, and you escape the quote to turn data
into code:

```
   "SELECT * FROM users WHERE name = '"  +  input  +  "'"
                                             ^^^^^
                                    you break out of the quotes
```

MongoDB has no query string to break out of. A query is a **data
structure** (a dict/JSON object) from the moment it's built:

```python
db.users.find_one({"name": user_input})
#                  ^^^^^^^^^^^^^^^^^^^^^^
#              already a dict, nothing to "escape"
```

So the bug is not a syntax break. It is a **type confusion**:

```
  expected:  user_input is a STRING   ->  {"name": "gon"}        (equality)
  attacker:  user_input is a DICT     ->  {"name": {"$ne": null}} (an OPERATOR)
```

MongoDB looks at the *value*. If the value is a plain scalar, it's an
equality test. If the value is a dict whose keys start with `$`, MongoDB
honors those keys as **query operators**. The application never meant to
let you pick the operator, it only meant to let you pick the value, but
it never checked the *type* of what you sent.

> **The whole bug class in one sentence:** if an app folds a
> request-supplied value into a Mongo query without first checking it is
> the primitive type expected (usually `str`), a caller who makes that
> value arrive as a dict controls the query *operator*, not just the
> operand.

---

## 2. How does a dict "arrive" instead of a string?

Two delivery channels, both common in real applications.

### (a) JSON body: the natural one

If the endpoint accepts JSON, nesting is free. `json.loads` builds real
nested dicts for you:

```
POST /login              Content-Type: application/json

{"username": "admin", "password": {"$ne": null}}
                                   ^^^^^^^^^^^^^^
                     already a Python dict after json.loads
```

### (b) Bracket notation: for form/query-string endpoints

A query string or form body is *flat* key/value pairs. Most web
frameworks do **not** auto-nest them. So some apps reconstruct nesting
from a bracket convention, letting a plain GET request carry the same
shape a JSON body would:

```
GET /records?value[$regex]=^SEIYAKU&value[$options]=i

   rebuilt by the app into:  {"value": {"$regex": "^SEIYAKU", "$options": "i"}}
```

> Not every app rebuilds bracket notation, but many frameworks and
> body-parsers (Express's `qs`, PHP, etc.) do it *by default*, which is
> why `param[$ne]=1` is a standard thing to try blind against any GET
> endpoint that takes a search/filter parameter.

---

## 3. The operator toolbox

These are standard, officially documented MongoDB query operators. The ones
that matter for injection:

| Operator | Means | Attack use |
|---|---|---|
| `$ne` | not equal | `{"$ne": null}` → matches any doc where field exists → **auth bypass** |
| `$gt` / `$lt` | greater / less than | lexicographic **bisection** of a hidden value |
| `$gte`/`$lte` | ≥ / ≤ | boundary variants of the above |
| `$regex` | regex match | prefix-walk a hidden value **one character at a time** |
| `$exists` | field present? | discover which fields a document even has |
| `$in` | value in list | test many candidates in one query |
| `$where` | run **JavaScript** | arbitrary JS predicate, time-based blind, see §7 |
| `$or` | logical OR of clauses | inject extra clauses, see §8 |

---

## 4. Pattern A: Authentication bypass

The sink is a two-field equality login:

```python
db.agents.find_one({"username": username, "password": password})
```

Intended: both are strings, both must match a real credential. Attack:
make `password` (and/or `username`) an operator that is **true without
knowing the real value**:

```
{"username": {"$ne": null}, "password": {"$ne": null}}
```

`$ne: null` is "not equal to null", true for *every* document that has
that field at all. The filter now matches every agent. `find_one` returns
the **first** document in natural order, and you're logged in as whoever
that is, in a real deployment, often whichever account was created
first, sometimes a seed/admin account inserted before any ordinary user.

```
  normal login:      {"username":"field.rose","password":"th0rn_and_petal"}
                     └─ matches exactly one real agent (if pw correct)

  injected login:    {"username":{"$ne":null},"password":{"$ne":null}}
                     └─ matches ALL agents ──> find_one returns doc #1
```

Delivery, two equivalent ways:

```
JSON:   {"username":{"$ne":null},"password":{"$ne":null}}
form:   username[$ne]=1&password[$ne]=1
```

> Variants worth knowing: `{"$gt": ""}` (greater than empty string: true
> for any non-empty string), `{"$ne": "x"}`, `{"$exists": true}`. If
> `$ne: null` is filtered, these often still work.

---

## 5. Pattern B: Blind extraction

Here the endpoint is an **oracle**: it tells you only *match / no-match*,
never the data. You still extract a full hidden string, one bit at a time,
by asking yes/no questions with operators.

### Method 1: `$regex` prefix walk

Ask "does the value start with this prefix?" and grow the prefix:

```
value[$regex]=^S          -> match?   yes   (it starts with S)
value[$regex]=^SE         -> match?   yes
value[$regex]=^SEA        -> match?   no
value[$regex]=^SEI        -> match?   yes   ... keep going
```

Each confirmed character extends the known prefix. Anchor with `^`
(start), and remember regex metacharacters in the *target* (`{`, `}` in
`SEIYAKU{...}`) must be escaped in your pattern (`\{`).

```
   KNOWN: "SEIYAKU{"            try next char c in [a-z0-9_]
        │
        ▼
   ^SEIYAKU\{a   no
   ^SEIYAKU\{b   no
   ^SEIYAKU\{c   yes  ──►  KNOWN becomes "SEIYAKU{c"   ──► repeat
        ...
   stop when ^...\}$ matches (you've hit the closing brace)
```

### Method 2: `$gt` / `$lt` bisection (faster)

Binary-search the value lexicographically instead of linear-scanning the
alphabet:

```
value[$gt] = "SEIYAKU{m"   -> is the secret > that?   narrows the range
value[$gt] = "SEIYAKU{t"   ...
```

`log2(charset)` queries per character instead of `charset/2` on average.
Same oracle, fewer requests.

### The blind-extraction loop (both methods)

```
        ┌─────────────────────────────────────────┐
        │  known_prefix = ""                        │
        └───────────────┬───────────────────────────┘
                        ▼
        ┌─────────────────────────────────────────┐
        │  for each candidate next-char / boundary: │
        │     send query(known_prefix + guess)      │◄────┐
        │     read oracle: matched? (true/false)    │     │
        └───────────────┬───────────────────────────┘     │
                        ▼                                  │
        ┌─────────────────────────────────────────┐       │
        │  on a hit: known_prefix += that char      │───────┘
        │  on full value (closing anchor matches):  │
        │     DONE                                   │
        └─────────────────────────────────────────┘
```

> If the *field name* itself is also unvalidated (not just its value),
> that lets you aim the oracle at *any* field on any document,
> including fields a normal search result never shows. Combine "which
> fields exist" (`$exists`) with the extraction loop to pull a value out
> of a field the UI never displays.

---

## 6. Pattern C: Error-based detection and exfiltration

PortSwigger's own NoSQLi methodology leads with this, *before* committing
to a slow blind campaign: fuzz the target with something deliberately
malformed and see what the database says about it.

### Detection: fuzz for an error

Submit an operator that doesn't exist:

```
value[$regexx]=x        -> OperationFailure: unknown operator: $regexx
```

A real application that swallows every exception into a generic
"no match" hides this entirely. One that doesn't (a realistic "verbose
errors left on for debugging" antipattern) confirms the injection exists
in a single request, no inference from match/no-match behavior required.

### Weaponization: `$expr` + `$convert` one-shot leak

MongoDB's `$expr` operator evaluates an aggregation expression as the
query predicate; nested inside it, `$toInt`/`$toDate`/`$convert` try to
cast a value to another type. Asked to convert a value that can't parse,
with no `onError` fallback supplied, the raised error **embeds the real
field value verbatim**:

```python
db.collection.find({
    "$expr": {"$eq": ["$secretField", {"$toInt": "$secretField"}]}
})
# OperationFailure: Failed to parse number 'SEIYAKU{...}' in $convert
# with no onError value: Did not consume whole string.
```

This is MongoDB's closest analogue to SQL's classic
`extractvalue()`/`updatexml()` error-based exfiltration trick: one
request, the whole value, no bit-at-a-time walking.

```
   fuzz a malformed operator
        │
        ▼
   error text distinct from "no match"?  ──no──►  errors are swallowed,
        │ yes                                     fall back to Pattern B
        ▼
   injection confirmed in ONE request
        │
        ▼
   target a string field with $expr + $toInt (or $toDate, …)
        │
        ▼
   conversion fails ──► error message contains the real value  ──► DONE
```

> `$expr` normally sits at the query's top level
> (`find({"$expr": {...}})`), not nested under a field name. If the
> *field name itself* is unvalidated (the same `field` an app folds into
> `{field: value}`, see §1), setting `field="$expr"` turns the entire
> query into a top-level `$expr` clause, reaching this technique through
> the same unvalidated-field bug Patterns A/B already rely on.

---

## 7. Pattern D: `$where` injection and time-based blind

`$where` is MongoDB's one operator that doesn't take a literal or another
operator as its value: it takes a string of **JavaScript**, evaluated by
the server once per document. That reopens a *string* context, so the
bug reverts to a classic quote-breakout, closer to traditional SQL
injection than to Patterns A-C's pure type confusion:

```python
db.users.find({"$where": f"this.name == '{input}'"})   # VULN
#   input = "x' || '1'=='1"   ->  this.name == 'x' || '1'=='1'  (all docs)
```

### Why this needs its own technique

If the response is blind in-band (no boolean, no error, sometimes a
deliberate design choice, sometimes just incomplete error handling), the
one thing left to read is **how long the query took**. `$where`'s JS
context exposes a real `sleep(ms)` function:

```
codename = x' || (REAL_CONDITION && sleep(400)) || '
```

A true `REAL_CONDITION` stalls the response by ~400ms; a false one
returns immediately. Binary-search a hidden value's length via
`.length`, then each character's code via `.charCodeAt(i)`, exactly the
same bisection shape as Pattern B's `$gt` walk, just read off a clock
instead of a response body:

```
   COND = this.secret.length>=15        -> slow (true)   -> length ≥ 15
   COND = this.secret.length>=29        -> slow (true)   -> length ≥ 29
   COND = this.secret.length>=30        -> fast (false)  -> length == 29

   COND = this.secret.charCodeAt(0)>=83 -> slow (true)   -> code ≥ 83
   COND = this.secret.charCodeAt(0)>=84 -> fast (false)  -> code == 83 ('S')
```

> **A real gotcha, worth knowing:** `count_documents()` is
> built on MongoDB's aggregation framework, which *rejects* `$where`
> inside a `$match` stage outright (`$where is not allowed in this
> context`). `find()` has no such restriction. The exact same `$where`
> clause behaves differently depending on which query method wraps it,
> not obvious from `$where`'s own documentation, confirmed by testing
> against a live server.

> **A quoting trap:** closing an injected JS string with `|| 'x'` (a
> non-empty string literal) looks like a closed quote but is a silent
> bug: JavaScript treats any non-empty string as truthy, so
> `(false) || (cond) || ('x')` is *always* true regardless of `cond`.
> Close with a single trailing `'` instead, so the template's own closing
> quote completes it into `''` (empty string, falsy, harmless).

### A third `$where` technique: direct leak via `throw`

Boolean breakout and time-based blind both treat `$where` as a yes/no
oracle, the same shape as every other blind technique in this doc. But
`$where` grants *arbitrary JavaScript execution*, not just a boolean
predicate, and JavaScript's `throw` statement can throw **any value**,
not just trigger a generic failure. If an application ever echoes a
query's raw exception text back to the caller (the same "verbose errors
left on" antipattern Pattern C is built around), a caller doesn't have to
ask yes/no questions at all. They can write JS that, on a match,
deliberately throws the exact field they want:

```js
function() { if (this.username == 'admin') { throw this.password; } return false; }
```

Confirmed live against a real MongoDB server:

```
db.credtest.find({"$where": "function(){ if(this.username=='admin'){throw this.password} return false }"})
->
OperationFailure: Executor error during find command :: caused by ::
uncaught exception: sup3r_s3cr3t_pw
```

The real password, verbatim, inside the error message, in **one
request**. This is meaningfully different from a type-conversion error
accidentally leaking a value (Pattern C's `$expr`/`$convert` trick): here
the thrown value is chosen on purpose, there's no guessing about whether
some unrelated conversion happens to fail.

The lesson this exposes: "the response is only ever a boolean" is a
property of the queries a *developer* imagined running, not a property
of what `$where` actually allows. A caller isn't limited to answering the
intended yes/no question; they can write completely different code that
does something the developer never pictured, like crashing on purpose
with the secret embedded in the crash. Closing this requires the same
fix as Pattern C: never let a `$where` (or any) query's raw exception
text reach the HTTP response, full stop, independent of how carefully
the *query itself* gets fixed.

---

## 8. Further techniques, beyond the four core patterns

### `$or` / logical-clause injection

Where an operator dict can carry `$or`, a caller can bolt on an
always-true clause:

```
{"filter": {"$or": [ {"realField": "x"}, {"1": {"$ne": 2}} ]}}
```

### Aggregation-pipeline injection beyond `$expr`

If request data reaches other `$match`/`$lookup` stages of an
aggregation pipeline, the same type-confusion applies in a richer
surface. Rare but high-impact.

---

## 9. Defense (the actual fix)

The root cause is **unvalidated type**, so the fix is at the boundary:

1. **Type-check before the query.** Reject anything that isn't the
   expected primitive:
   ```python
   if not isinstance(value, str):
       abort(400)
   db.records.count_documents({field: value})
   ```
   This single check kills every operator-injection payload at once,
   because a dict can never reach the query.

2. **Validate `field` against an allow-list** too, never let the caller
   name an arbitrary field.

3. **Schema validation at the edge** (pydantic / JSON-schema / cerberus):
   declare "username is a string", and the framework rejects a nested
   object before your code ever sees it.

4. **Avoid `$where`/server-side JS entirely wherever a native operator can
   express the same check**, and disable it at the deployment level when
   nothing legitimately needs it (`--noscripting` /
   `security.javascriptEnabled: false`). There is no safe parameterization
   for `$where`: the string *is* the code, so the only real fix for an
   existing `$where` sink is not building it from untrusted input, full
   stop.

5. **Never return raw driver exception text in an HTTP response.** This
   is what makes Pattern C's one-shot leak possible: log the real
   exception server-side, return a generic failure to the caller.

6. **Least privilege** on the DB user, as always: a read-only app role
   can't be turned into a write/drop even after a successful read
   injection.

> Note what is *not* the fix: "escaping." There's no quote to escape in
> Patterns A-C. Sanitizing `$` out of strings is a brittle band-aid; the
> correct fix is enforcing the *type*. Pattern D (`$where`) is the one
> exception: there, you're back in string-escaping territory, except the
> only safe answer is "don't build the string from untrusted input," not
> "escape it correctly."

---

## 10. References (official / primary)

- **PortSwigger Web Security Academy, NoSQL injection:**
  https://portswigger.net/web-security/nosql-injection (the four-pattern
  taxonomy, operator/syntax injection, boolean-based, time-based, and
  error-based, that this doc follows)
- **MongoDB query operators:** https://www.mongodb.com/docs/manual/reference/operator/query/
  (`$ne`, `$gt`, `$regex`, `$exists`, `$where`, `$expr`, …)
- **MongoDB `$where`:** https://www.mongodb.com/docs/manual/reference/operator/query/where/
- **MongoDB `$convert` / `$toInt` / `onError`:**
  https://www.mongodb.com/docs/manual/reference/operator/aggregation/convert/
  (the `onError` parameter's documented purpose is suppressing the
  default conversion-failure behavior Pattern C exploits)
- **OWASP Testing Guide, Testing for NoSQL Injection** (WSTG-INPV-05):
  https://owasp.org/www-project-web-security-testing-guide/
- **OWASP Cheat Sheet, Injection Prevention / Input Validation:**
  https://cheatsheetseries.owasp.org/
- **PyMongo type behavior:** https://pymongo.readthedocs.io/
