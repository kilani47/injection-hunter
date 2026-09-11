# Injection Hunter

[![License: MIT](https://img.shields.io/badge/code%20license-MIT-blue.svg)](LICENSE)
[![Challenges](https://img.shields.io/badge/challenges-18-informational.svg)](docs/traceability.md)
[![Backends](https://img.shields.io/badge/real%20backends-MariaDB%20%7C%20MongoDB%20%7C%20OpenLDAP%20%7C%20lxml-informational.svg)](docker-compose.yml)

A full-spectrum injection-attack training lab. Eighteen challenges, each
one running against a real backend engine, no simulated responses
anywhere: error-based, union-based, boolean-blind, and time-blind SQL
injection; SQLMap methodology against real targets; out-of-band and
second-order SQLi; NoSQL operator injection; LDAP injection; ORM
injection; and XML/XXE, closing with two chained, multi-vulnerability
final exams.

The lab ships under its own name, **The Seiyaku Arc**: a Hunter Exam-themed
narrative where each phase is an examiner enforcing one Vow (an
input-validation rule) against that real infrastructure. Every Vow has a
loophole the examiner never anticipated. Find it, and the flag it yields
unlocks the next floor.

**Complete**, all 18 nodes across 5 phases and 2 Finals are built and
solver-verified end to end against real, freshly-seeded backends. See
[`docs/traceability.md`](docs/traceability.md) for the full notes-to-challenge
coverage matrix.

This is an **unofficial fan project**, see [Legal / Disclaimer](#legal--disclaimer)
below before you do anything else with it.

## 📖 Which doc do you want?

| I want to... | Read |
|---|---|
| **Play the arc** as a blackbox challenge | Start at the hub (`/hub`) once running, each floor's own `CHALLENGER.md` (linked from its phase's `README.md` below) is the spoiler-free briefing. |
| **Check my work**, or understand *why* a payload worked | That floor's own `DEBRIEF.md`, root cause, code walkthrough, an HxH analogy, the real payloads and live solver output, and remediation. |
| See **every notes topic mapped to its challenge** | [`docs/traceability.md`](docs/traceability.md) |
| Understand how it's **built** | keep reading below |

## Premise

You are an applicant. Six phases stand between you and a Hunter License:

| Phase | Location | Nen category | Topic cluster | Docs |
|------:|----------|---------------|----------------|------|
| 1 | The Written Exam | Enhancement (crimson) | SQLi fundamentals + the 4 core techniques | [`phase1/`](phase1/README.md) |
| 2 | Trick Tower | Transmutation (violet) | Testing methodology + SQLMap + header/CVE labs | [`phase2/`](phase2/README.md) |
| 3 | Greed Island | Specialization (gold) | Out-of-band + second-order SQLi | [`phase3/`](phase3/README.md) |
| 4 | Hunter Association HQ | Manipulation (green) | NoSQL + LDAP injection | [`phase4/`](phase4/README.md) |
| 5 | Chimera Ant Palace | Conjuration (indigo) | ORM injection + XML/XXE | [`phase5/`](phase5/README.md) |
| Finals | The Exam Finals | Emission (cyan) | Two chained, multi-engine CTFs | [`finals/`](finals/README.md) |

18 challenges total, covering every injection class in the lab's source
notes end to end. Clearing a challenge reveals a flag in the format
`SEIYAKU{lowercase_snake_words}`, submit it on the hub to unlock the next
floor and trigger the victory screen.

Every challenge ships two docs: a spoiler-free `CHALLENGER.md` (the
blackbox briefing) and a full `DEBRIEF.md` (root cause, code walkthrough,
an HxH analogy, the real payloads and live solver transcripts, and
remediation).

## Running it

Everything is orchestrated by Docker Compose, `flask` (the portal),
`mariadb`, `mongo`, `openldap`, and `collaborator` (the Phase 3 OOB
callback catcher).

```bash
docker compose up -d
# portal now listening on http://localhost:8000
./solvers/smoke.sh
```

Every node is independently solvable, see `solvers/` for a canonical,
live-verified exploit script per node (`p1_1.sh` … `p5_3.sh`, `f1.py`,
`f2.py`). Each one runs the real technique against the real running stack
and asserts the exact flag.

To reset your progress: visit `/reset`, or restart the `flask` container
(progress lives in the signed session cookie, not a database).

**First boot vs. an existing volume:** MariaDB/MongoDB/OpenLDAP only run
their `*.sql`/`*.js`/`*.ldif` seed files on first boot of an *empty* data
volume. If you add or modify a seed file against a stack that's already
been started once, either apply it manually (see any `feat(...)` commit
that added a seed file after the initial scaffold for the exact
`docker compose exec` incantation used) or start fresh:

```bash
docker compose down -v && docker compose up -d
```

### Local development without Docker

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python app.py   # http://localhost:8000
```

Note: `python-ldap` needs `libldap2-dev`/`libsasl2-dev` (or your distro's
equivalent) on the host to build outside the container.

### Rebuilding the CSS

`static/css/nen.css` is a committed Tailwind build output (see
`static/css/src/input.css` for the actual design-system source and
`tailwind.config.js` for the theme). To rebuild after touching a template:

```bash
npm install
npm run build
```

## Legal / Disclaimer

**Unofficial fan project.** Not affiliated with, endorsed by, or sponsored
by Yoshihiro Togashi, Shueisha, VIZ Media, the Hunter × Hunter anime
production committee, or any other rights holder. For local, authorized,
educational use only, do not deploy this on a network you don't control or
don't have explicit authorization to test.

The MIT `LICENSE` in this repository covers **only** the original code,
markup, and writing authored here. Hunter × Hunter names, terminology, and
imagery are unlicensed third-party property, used unofficially and
non-commercially for educational theming. Full detail in `NOTICE`.

**Plain-language risk statement:** the lab's default victory screen is an
original CSS animation and ships with zero third-party image/video files.
Separately, `static/img/victory/<node-id>.gif` is an *opt-in* slot an
operator can fill locally with a Hunter × Hunter clip (see
`assets/README.md` / `assets/fetch-assets.sh`), but no license, including
this one, can grant rights to someone else's copyrighted frames. Adding such
a file is a residual legal risk the operator accepts personally, not
something this project's license covers or protects. Leaving the slot empty
avoids that risk entirely and is the default state of a fresh clone.

## Ethics

Authorized, local use only. Every vulnerable engine in this lab runs on your
own machine, seeded with synthetic data. Do not point any technique taught
here at a system you don't own or don't have explicit written authorization
to test.
