# Phase 5 — Chimera Ant Palace

**Nen category:** Conjuration (indigo) &middot; **Engines:** MariaDB (via a real SQLAlchemy ORM), a real XML parser &middot; **Topic cluster:** ORM injection, then XML/XXE — hidden structure beneath a layer that looks solid from the outside.

The Palace's outer defenses look nothing like the raw, hand-built
queries of Phases 1-3: a real ORM sits in front of the database, and a
real XML parser sits in front of the document pipeline. Conjuration is
the Nen category built around materializing something that looks and
behaves like the real thing but was assembled by the conjurer's own
rules — an apt name for a phase where every bug lives in structure that
*looks* trustworthy (an ORM call, a well-formed XML document) but was
built, underneath, exactly the same unsafe way the earlier phases'
raw queries were.

## Rules of engagement

- Everything runs locally, against a real MariaDB instance (through a
  real SQLAlchemy ORM layer) and a real XML parser. Authorized, local
  use only — see the repository [`NOTICE`](../NOTICE) and
  [`README.md`](../README.md#ethics).
- No source code, hints, or automated scanners are off-limits — this is
  a whitebox-friendly lab. Reading `challenges/phase5.py` is not
  cheating.
- Each floor has its own directory under `phase5/` with two documents:
  - `CHALLENGER.md` — the blackbox briefing. Read this first. No
    solution.
  - `DEBRIEF.md` — full spoilers: root cause, the walk, remediation.
    Read this after you've either solved the floor or want to
    understand why a payload worked.
- Flags are `SEIYAKU{lowercase_snake_words}`. Submit on the hub
  (`/hub`) to unlock the next floor.

## Floors

| # | Node | Directory | Status |
|---|------|-----------|--------|
| 1 | Manipulator's Firewall | [`manipulators-firewall/`](manipulators-firewall/) | built |
| 2 | Palace Blueprint Tampering | [`blueprint-tampering/`](blueprint-tampering/) | built |
| 3 | The King's Sealed Archives | — | not yet built |

"Manipulator's Firewall" shows that an ORM is not automatically a fix
for injection: SQLAlchemy parameterizes everything that goes through
its own query-building API, but it also exposes a raw-SQL escape hatch
(`text()`) for cases that API can't express — and an f-string spliced
into that escape hatch is exactly as injectable as no ORM at all. The
classic `' OR '1'='1' -- ` payload from Phase 1 works here completely
unchanged; only the layer that builds the final SQL string is new.

"Palace Blueprint Tampering" moves from a SQL string to an XML document
built the same unsafe way: a visitor name spliced into an XML template
with none of XML's five reserved characters (`< > & ' "`) escaped
first. The parser (`core/xml_parser.py`, shared with the next floor)
genuinely enforces well-formedness — a stray `<` is rejected outright —
but a *well-formed* document with extra, attacker-added structure is,
correctly, accepted, letting a crafted name add a second `<clearance>`
element that a naive first-match lookup reads instead of the
template's own.
