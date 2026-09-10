# The Exam Finals

**Nen category:** Emission (cyan) &middot; **Engines:** every real backend from every earlier phase &middot; **Topic cluster:** chained, multi-vuln exploitation — projecting everything learned across the whole arc at once.

Every earlier phase taught one topic cluster in isolation. The Finals
don't teach anything new — they test whether what you learned actually
composes: whether you can recognize which of five injection classes a
locked door is asking for, extract exactly what it's guarding, and use
that to open the next one. Emission is the Nen category for projecting
your aura outward, independent of your body — an apt name for a phase
that's no longer about any single technique, but about applying
everything you've built up so far, at range, against a target that
demands more than one skill at once.

## Rules of engagement

- Everything runs locally, against the same real backends every earlier
  phase used. Authorized, local use only — see the repository
  [`NOTICE`](../NOTICE) and [`README.md`](../README.md#ethics).
- No source code, hints, or automated scanners are off-limits — this is
  a whitebox-friendly lab. Reading `challenges/finals.py` is not
  cheating.
- Each final has its own directory under `finals/` with two documents:
  - `CHALLENGER.md` — the blackbox briefing. Read this first. No
    solution.
  - `DEBRIEF.md` — full spoilers: root cause, the walk, remediation.
    Read this after you've either solved it or want to understand why a
    payload worked.
- Flags are `SEIYAKU{lowercase_snake_words}`. Submit on the hub
  (`/hub`) to unlock the next node.

## Finals

| # | Node | Directory | Status |
|---|------|-----------|--------|
| 1 | Trick Tower Final Exam (BookHaven) | [`trick-tower-final/`](trick-tower-final/) | built |
| 2 | Chairman Election Infiltration (OmniGrid) | [`chairman-election/`](chairman-election/) | built |

"Trick Tower Final Exam" chains all four of Phase 1's core SQLi
techniques (error-based, union-based, boolean-blind, time-blind) into
one four-stage descent: each stage's vulnerable query is inert until the
*previous* stage's real, extracted key is supplied as that stage's
`token` — a genuinely safe, parameterized gate, not a cosmetic one. There
is no shortcut past a stage except actually running its real technique.

"Chairman Election Infiltration" closes the whole arc with four
*independent* faction systems instead of one chain: MariaDB (error-based
SQLi), MongoDB (`$ne` auth bypass), OpenLDAP (filter-injection dump), and
XXE (external-entity file read) — every one of them the identical bug
shape as a floor already solved earlier in the arc, on an unfamiliar
target with no narrative hint pointing at which technique it wants. A
final `/f/omnigrid/seize` endpoint independently re-derives all four
factions' real current values via safe, non-injectable lookups and grants
the flag only when every submitted fragment genuinely matches.

The Seiyaku Arc is now complete end-to-end: every phase, every floor, and
both finals are solvable against real MariaDB, MongoDB, OpenLDAP, and a
real XML parser, with no simulated or hardcoded responses anywhere in the
chain.
