# Phase 1 — The Written Exam

**Nen category:** Enhancement (crimson) &middot; **Engine:** MariaDB &middot; **Topic cluster:** SQL injection fundamentals + the four core blind/error/union/time techniques.

You are seated for the Hunter Exam's written portion. Every examiner in this
phase enforces one Vow — a rule about what an applicant's input is allowed
to mean. Every Vow here is worded just loosely enough to be misread.

## Rules of engagement

- Everything runs locally, against real backend engines seeded with
  synthetic data. Authorized, local use only — see the repository
  [`NOTICE`](../NOTICE) and [`README.md`](../README.md#ethics).
- No source code, hints, or automated scanners are off-limits — this is a
  whitebox-friendly lab. Reading `challenges/phase1.py` is not cheating; the
  point is understanding the sink well enough to explain it afterward.
- Each floor has its own directory under `phase1/` with two documents:
  - `CHALLENGER.md` — the blackbox briefing. Read this first. No solution.
  - `DEBRIEF.md` — full spoilers: root cause, the walk, remediation. Read
    this after you've either solved the floor or want to understand why a
    payload worked.
- Flags are `SEIYAKU{lowercase_snake_words}`. Submit on the hub (`/hub`) to
  unlock the next floor.

## Floors

| # | Node | Directory | Status |
|---|------|-----------|--------|
| 1 | Gate of Trust | [`gate-of-trust/`](gate-of-trust/) | built |
| 2 | Netero's Recipe Vault | [`recipe-vault/`](recipe-vault/) | built |
| 3 | Exam Results Board | [`results-board/`](results-board/) | built |
| 4 | Trick Tower — Silent Room | [`silent-room/`](silent-room/) | built |
| 5 | Zevil Island Medical Bay | *(lands with Task 1.5)* | not yet built |

This table grows one row per Phase-1 task; no other edits are expected here
once a floor lands beyond flipping its status and linking its directory.
