# Phase 4, Hunter Association HQ

**Nen category:** Manipulation (green) &middot; **Engines:** MongoDB (floors 1-4) + OpenLDAP (floors 5-6) &middot; **Topic cluster:** NoSQL and LDAP injection, beginner through intermediate, the same "attacker text becomes attacker-controlled logic" idea as Phases 1-3, now landing on a query language built out of native data structures (MongoDB) and then a different string grammar entirely (LDAP).

Every earlier phase's injection worked by escaping a quote: attacker
input broke out of a string context and became new SQL. MongoDB's own
query language has no string context to escape in the first place, a
query is just a Python (or JSON) dict from the moment it's built. That
makes the bug class here a *type* confusion instead of a *syntax*
break: if an application ever hands MongoDB a value it received from a
caller without first checking what type that value actually is, and a
caller manages to make that value arrive as a dict instead of a plain
string, MongoDB doesn't compare the dict as a literal, it honors it as
real operators (`$regex`, `$gt`, `$ne`, `$exists`, `$where`, ...).
Manipulation is the Nen category built around making something act on
your behalf without it announcing that it's happened, an apt name for a
bug class where the database faithfully does exactly what a crafted
request asked of it, and the application never notices the request
wasn't the shape it expected.

Floors 5-6 move off MongoDB entirely into the lab's real OpenLDAP
directory, a completely different query language and bug *shape*: LDAP
search filters (RFC 4515) are a string grammar again, so the root cause
there rhymes with Phases 1-3's classic SQLi, just against a different
grammar of special characters (`( ) & | ! *`) instead of a quote.

## Rules of engagement

- Everything runs locally, against real MongoDB and real OpenLDAP
  instances seeded with synthetic data. Authorized, local use only, see
  the repository [`NOTICE`](../NOTICE) and
  [`README.md`](../README.md#ethics).
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
- New to NoSQL or LDAP injection entirely? [`docs/learn-nosql-injection.md`](../docs/learn-nosql-injection.md)
  and [`docs/learn-ldap-injection.md`](../docs/learn-ldap-injection.md)
  are from-scratch primers covering both engines' full technique
  landscape (including a couple of things no single floor below drills
  on its own), worth reading before floor 1.

## Floors

Ordered beginner &rarr; intermediate: NoSQL first (operator injection,
then error-based, then boolean-blind, then the JS/timing escalation),
LDAP second (filter injection with a dump shortcut, then the harder
fully-blind variant).

| # | Node | Floor | Directory | Technique |
|---|------|-------|-----------|-----------|
| 1 | `p4_1` | Bypassing the Archive Guardian | [`archive-guardian/`](archive-guardian/) | operator injection &middot; auth bypass |
| 2 | `p4_2` | The Diagnostic Desk | [`diagnostic-desk/`](diagnostic-desk/) | operator injection &middot; error-based detection + one-shot leak |
| 3 | `p4_3` | Basic Records Room | [`records-room/`](records-room/) | operator injection &middot; boolean-blind extraction |
| 4 | `p4_4` | The Loophole Clause | [`loophole-clause/`](loophole-clause/) | `$where` (JS) injection &middot; time-based blind |
| 5 | `p4_5` | Zodiac Twelve Directory Breach | [`zodiac-breach/`](zodiac-breach/) | LDAP filter injection &middot; auth bypass + directory dump |
| 6 | `p4_6` | The Silent Directory | [`silent-directory/`](silent-directory/) | LDAP filter injection &middot; blind substring extraction |

**"Bypassing the Archive Guardian"** is the gentlest floor in the phase:
a classic `{"$ne": null}`-style login bypass against the `agents`
collection, the single most common real-world NoSQL injection payload,
first because it needs no multi-request walk at all, one payload, one
response, done.

**"The Diagnostic Desk"** teaches the technique a real methodology
reaches for *before* committing to a slow blind walk: this console
doesn't swallow MongoDB's own driver exceptions. A malformed operator
confirms the injection in one request; `$expr` + `$toInt`'s
conversion-failure error message leaks an entire field's value, verbatim,
in one more, MongoDB's closest analogue to SQL's `extractvalue()` trick.

**"Basic Records Room"** is the blind extraction lesson: the archive
search console reports only whether a query matched anything, never what
it matched, and neither the field name nor the value it searches on is
type-checked before reaching MongoDB, enough on its own to walk a hidden
value out one character at a time via `$regex`/`$gt`.

**"The Loophole Clause"** is this cluster's escalation: a `$where` sink
reopens a *string* context (JavaScript source, built by concatenation),
a different bug shape from the first three floors' pure type confusion.
The response is deliberately blind in-band (no boolean, no error), so
the only channel left is response timing via `$where`'s own `sleep()`,
time-based blind NoSQLi, the one PortSwigger-documented technique the
first three floors don't cover.

**"Zodiac Twelve Directory Breach"** moves off MongoDB entirely and into
the lab's real OpenLDAP directory (`ou=zodiac`), a different query
language with its own small grammar of special characters. A search
filter built by raw string concatenation, none of those characters
escaped, lets a caller rewrite the filter's own logic, enough for both
an authentication bypass and a full directory dump that surfaces
something the Zodiac Twelve's chairman was never meant to hand out
through an ordinary lookup.

**"The Silent Directory"** closes the phase with LDAP's missing
technique: a verification endpoint whose response is strictly boolean,
never attributes, ruling out Zodiac Breach's dump-mode shortcut
entirely. The only way through is the same blind, char-by-char substring
walk Records Room teaches for MongoDB, now expressed in RFC 4515's
wildcard grammar, against a seeded entry kept in a separate subtree
(`ou=registrar`) so it's unreachable through the other LDAP floor's own
injection.

Phase 4 is complete across all six floors: every route in
`challenges/phase4.py` runs against a real backend (MongoDB for floors
1-4, OpenLDAP for floors 5-6) with no simulated or hardcoded responses
anywhere in the chain.
