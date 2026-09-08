# Phase 3 — Greed Island

**Nen category:** Specialization (gold) &middot; **Engine:** MariaDB (+ the `collaborator` out-of-band service) &middot; **Topic cluster:** injection findings that don't show up where — or when — you'd expect them to.

Greed Island runs on its own rules: a card game layered over the real
world, where every card resolves through a game master who reads the
card, applies its effect, and reports back only the barest possible
outcome — and where some cards don't even resolve on the turn they're
played at all. Both of this phase's floors take the same classic SQL
injection primitive from Phases 1-2 and hide it somewhere ordinary
in-band testing doesn't think to look: the first floor strips the
response of any observable signal at all, forcing an out-of-band
channel; the second floor moves the payload's execution to an entirely
different request than the one that delivered it. Neither floor is
harder to *exploit* once you've spotted the shape — both are harder to
*notice* in the first place.

## Rules of engagement

- Everything runs locally, against real backend engines seeded with
  synthetic data — including a `collaborator` lab service that only
  exists to observe out-of-band traffic. Authorized, local use only — see
  the repository [`NOTICE`](../NOTICE) and [`README.md`](../README.md#ethics).
- No source code, hints, or automated scanners are off-limits — this is a
  whitebox-friendly lab. Reading `challenges/phase3.py` is not cheating.
- Each card has its own directory under `phase3/` with two documents:
  - `CHALLENGER.md` — the blackbox briefing. Read this first. No solution.
  - `DEBRIEF.md` — full spoilers: root cause, the walk, remediation. Read
    this after you've either solved the card or want to understand why a
    payload worked.
- Flags are `SEIYAKU{lowercase_snake_words}`. Submit on the hub (`/hub`) to
  unlock the next card.

## Cards

| # | Node | Directory | Status |
|---|------|-----------|--------|
| 1 | The Spell Card | [`spell-card/`](spell-card/) | built |
| 2 | The Cursed Card | [`cursed-card/`](cursed-card/) | built |

Clearing "The Spell Card" unlocks "The Cursed Card" — a second-order
(stored) SQL injection lesson: a safe, parameterized storage step whose
payload only executes later, in a separate route that reads it back out
of the database and trusts it. Clearing "The Cursed Card" completes Phase
3 and unlocks Phase 4.
