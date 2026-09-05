# The Seiyaku Arc

> *Every Nen ability is governed by a vow the caster wrote for themselves —
> and every vow hides a loophole its author never saw.*

The Seiyaku Arc is a single-site, deliberately-vulnerable web security lab
themed around the Hunter Exam. Each phase is an examiner enforcing one Vow
(an input-validation rule) against a **real** backend engine — MariaDB,
MongoDB, OpenLDAP, and an in-process XML parser. Every Vow has a loophole.
Find it, and the flag it yields unlocks the next floor.

This is an **unofficial fan project** — see [Legal / Disclaimer](#legal--disclaimer)
below before you do anything else with it.

## Premise

You are an applicant. Six phases stand between you and a Hunter License:

| Phase | Location | Nen category | Topic cluster |
|------:|----------|---------------|----------------|
| 1 | The Written Exam | Enhancement (crimson) | SQLi fundamentals + the 4 core techniques |
| 2 | Trick Tower | Transmutation (violet) | Testing methodology + SQLMap + header/CVE labs |
| 3 | Greed Island | Specialization (gold) | Out-of-band + second-order SQLi |
| 4 | Hunter Association HQ | Manipulation (green) | NoSQL + LDAP injection |
| 5 | Chimera Ant Palace | Conjuration (indigo) | ORM injection + XML/XXE |
| Finals | The Exam Finals | Emission (cyan) | Two chained, multi-engine CTFs |

18 challenges total, covering every injection class in the lab's source
notes end to end. Clearing a challenge reveals a flag in the format
`SEIYAKU{lowercase_snake_words}` — submit it on the hub to unlock the next
floor and trigger the victory screen.

Every challenge ships two docs once its task lands: a spoiler-free
`CHALLENGER.md` (the blackbox briefing) and a full `DEBRIEF.md` (root cause,
code walkthrough, an HxH analogy, the real payloads, and remediation).

## Status

This repository currently contains the **scaffold**: the portal, the Nen
aura design system, the progressive-unlock engine, the victory screen, and
this legal pack. Individual challenges land phase by phase — see
`docs/superpowers/plans/2026-09-05-seiyaku-arc.md` for the build plan. Until
a phase's blueprint lands, its nodes show on the hub as **locked** (or, for
the very first node, "unlocked · in development").

## Running it

Everything is orchestrated by Docker Compose. The `flask` service is the
portal; `mariadb`, `mongo`, `openldap`, and `collaborator` are declared for
later phases to wire up.

```bash
docker compose up -d flask
# portal now listening on http://localhost:8000
./solvers/smoke.sh
```

To reset your progress: visit `/reset`, or restart the `flask` container
(progress lives in the signed session cookie, not a database).

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
educational use only — do not deploy this on a network you don't control or
don't have explicit authorization to test.

The MIT `LICENSE` in this repository covers **only** the original code,
markup, and writing authored here. Hunter × Hunter names, terminology, and
imagery are unlicensed third-party property, used unofficially and
non-commercially for educational theming. Full detail in `NOTICE`.

**Plain-language risk statement:** the lab's default victory screen is an
original CSS animation and ships with zero third-party image/video files.
Separately, `static/img/victory/<node-id>.gif` is an *opt-in* slot an
operator can fill locally with a Hunter × Hunter clip (see
`assets/README.md` / `assets/fetch-assets.sh`) — but no license, including
this one, can grant rights to someone else's copyrighted frames. Adding such
a file is a residual legal risk the operator accepts personally, not
something this project's license covers or protects. Leaving the slot empty
avoids that risk entirely and is the default state of a fresh clone.

## Ethics

Authorized, local use only. Every vulnerable engine in this lab runs on your
own machine, seeded with synthetic data. Do not point any technique taught
here at a system you don't own or don't have explicit written authorization
to test.
