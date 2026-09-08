# Phase 3 — Greed Island

**Nen category:** Specialization (gold) &middot; **Engine:** MariaDB (+ the `collaborator` out-of-band service) &middot; **Topic cluster:** confirming a finding when the application's own response tells you nothing at all.

Greed Island runs on its own rules: a card game layered over the real
world, where every card resolves through a game master who reads the
card, applies its effect, and reports back only the barest possible
outcome. Most floors in this exam eventually give you *something* back —
a row, an error, a delay you can time. Greed Island's cards don't. The
whole phase is built around the moment testing methodology runs out of
in-band signal and has to find another channel entirely.

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
| 2 | The Cursed Card | *(coming soon)* | not yet built |

Clearing "The Spell Card" unlocks "The Cursed Card" — a second-order
injection lesson, not yet part of this phase's build. See
`.superpowers/sdd/2026-09-05-seiyaku-arc/` for the overall build plan.
