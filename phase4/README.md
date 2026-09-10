# Phase 4, Hunter Association HQ

**Nen category:** Manipulation (green) &middot; **Engine:** MongoDB &middot; **Topic cluster:** NoSQL injection, the same "attacker text becomes attacker-controlled logic" idea as Phases 1-3, but landing on a query language built out of native data structures instead of a string you have to break out of.

Every earlier phase's injection worked by escaping a quote: attacker
input broke out of a string context and became new SQL. MongoDB's own
query language has no string context to escape in the first place, a
query is just a Python (or JSON) dict from the moment it's built. That
makes the bug class here a *type* confusion instead of a *syntax*
break: if an application ever hands MongoDB a value it received from a
caller without first checking what type that value actually is, and a
caller manages to make that value arrive as a dict instead of a plain
string, MongoDB doesn't compare the dict as a literal, it honors it as
real operators (`$regex`, `$gt`, `$ne`, `$exists`, ...). Manipulation is
the Nen category built around making something act on your behalf
without it announcing that it's happened, an apt name for a bug class
where the database faithfully does exactly what a crafted request asked
of it, and the application never notices the request wasn't the shape
it expected.

## Rules of engagement

- Everything runs locally, against a real MongoDB instance seeded with
  synthetic data. Authorized, local use only, see the repository
  [`NOTICE`](../NOTICE) and [`README.md`](../README.md#ethics).
- No source code, hints, or automated scanners are off-limits, this is
  a whitebox-friendly lab. Reading `challenges/phase4.py` is not
  cheating.
- Each floor has its own directory under `phase4/` with two documents:
  - `CHALLENGER.md`, the blackbox briefing. Read this first. No
    solution.
  - `DEBRIEF.md`, full spoilers: root cause, the walk, remediation.
    Read this after you've either solved the floor or want to
    understand why a payload worked.
- Flags are `SEIYAKU{lowercase_snake_words}`. Submit on the hub
  (`/hub`) to unlock the next floor.

## Floors

| # | Node | Directory | Status |
|---|------|-----------|--------|
| 1 | Basic Records Room | [`records-room/`](records-room/) | built |
| 2 | Bypassing the Archive Guardian | [`archive-guardian/`](archive-guardian/) | built |
| 3 | Zodiac Twelve Directory Breach | [`zodiac-breach/`](zodiac-breach/) | built |

"Basic Records Room" is a blind extraction lesson: the archive search
console reports only whether a query matched anything, never what it
matched, and neither the field name nor the value it searches on is
type-checked before reaching MongoDB, which is enough on its own to
walk a hidden value out one character at a time via `$regex`/`$gt`.

"Bypassing the Archive Guardian" moves the same type-confusion bug
class from a read path to an auth check, the classic `{"$ne": null}`
-style login bypass, against the `agents` collection seeded alongside
`records` in this floor's Mongo data.

"Zodiac Twelve Directory Breach" closes the phase by moving off MongoDB
entirely and into the lab's real OpenLDAP directory (`ou=zodiac`), a
different query language with its own small grammar of special
characters (`( ) & | ! *`), and a different bug *shape* even though the
root cause rhymes with the first two floors: a search filter built by
raw string concatenation, with none of those characters escaped before
request-supplied text reaches it, lets a caller rewrite the filter's
own logic instead of just supplying a value for it to compare against,
enough for both an authentication bypass and a full directory dump that
surfaces something the Zodiac Twelve's chairman was never meant to hand
out through an ordinary lookup.

Phase 4 is complete across all three floors: every route in
`challenges/phase4.py` runs against a real backend (MongoDB for the
first two floors, OpenLDAP for the third) with no simulated or
hardcoded responses anywhere in the chain.
