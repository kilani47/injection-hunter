# Phase 2 — Trick Tower

**Nen category:** Transmutation (violet) &middot; **Engine:** MariaDB (+ later floors) &middot; **Topic cluster:** testing methodology, SQLMap, and the kind of loophole that hides in a header instead of a form field.

Trick Tower is a game of enforced rules. Every applicant is told the exact
shape of the test — how many floors, what each door demands — and the
whole exam is built on the assumption that nobody tests those rules
faster than a human reasonably could. That assumption is Phase 2's Vow.

## Rules of engagement

- Everything runs locally, against real backend engines seeded with
  synthetic data. Authorized, local use only — see the repository
  [`NOTICE`](../NOTICE) and [`README.md`](../README.md#ethics).
- No source code, hints, or automated scanners are off-limits — this is a
  whitebox-friendly lab. Reading `challenges/phase2.py` is not cheating;
  the point of this phase in particular is learning to *drive* a scanner
  well, not avoiding one.
- Each floor has its own directory under `phase2/` with two documents:
  - `CHALLENGER.md` — the blackbox briefing. Read this first. No solution.
  - `DEBRIEF.md` — full spoilers: root cause, the walk, remediation. Read
    this after you've either solved the floor or want to understand why a
    payload (or a scan) worked.
- Flags are `SEIYAKU{lowercase_snake_words}`. Submit on the hub (`/hub`) to
  unlock the next floor.

## Floors

| # | Node | Directory | Status |
|---|------|-----------|--------|
| 1 | Automated Floor Skip | [`automated-floor-skip/`](automated-floor-skip/) | built |
| 2 | A Sealed Floor | [`sealed-floor/`](sealed-floor/) | built |
| 3 | The Disguised Examiner | _(lands in a later task)_ | not yet built |

Floor 1 is built. Floors 2 and 3 will fill in as their tasks land — see
`.superpowers/sdd/2026-09-05-seiyaku-arc/` for the build plan. Until a
floor's blueprint lands, its node shows on the hub as **locked**.
