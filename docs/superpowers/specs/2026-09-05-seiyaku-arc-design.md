# THE SEIYAKU ARC — Design Spec

> **Advanced Injection through the Hunter Exam.**
> A single-site, deliberately-vulnerable CTF lab that teaches every injection
> class in the master notes, themed around Hunter × Hunter's central idea:
> **Nen abilities are governed by self-imposed rules (誓約 *Seiyaku* — Vows &
> Limitations), and every rule hides a loophole the caster never anticipated.**
> That *is* injection: a system trusts its own input-validation rule; the
> attacker finds where the rule was worded imprecisely and breaks out of *data*
> into *code*.

- **Arc name (chosen):** **The Seiyaku Arc** — "The Vow-Breaker's Exam."
- **Repo:** `seiyaku-arc`
- **Author:** abdullah.kilani4702@gmail.com
- **Status:** design / pre-implementation
- **Date:** 2026-09-05

---

## 1. Goals & non-goals

**Goals**
1. One challenge for **every topic in the master notes** — nothing skipped. Full
   traceability matrix in §4.
2. **Realistic**: exploits run against **real engines** (MariaDB, MongoDB,
   OpenLDAP, a real XML parser). Payloads from the notes work verbatim.
3. **Educational**: every challenge ships a spoiler-free `CHALLENGER.md`
   (briefing) and a full `DEBRIEF.md` (root cause, code walkthrough, HxH analogy,
   step-by-step solve, remediation, self-check).
4. **Fun + amazing design**: Tailwind + a custom "Nen aura" design system, each
   phase colour-keyed to a Nen category, animated victory screens, progressive
   phase unlock like the Hunter Exam.
5. **Legally defensible**: MIT over original code/writing + a strong
   unofficial-fan-project disclaimer and asset scope note. (See §9.)

**Non-goals**
- Not a real-world exploit toolkit; all targets are local, intentionally weak.
- No internet-facing deployment; localhost lab only.
- Not affiliated with, endorsed by, or licensed from any rights holder.

---

## 2. The narrative frame

You are an **applicant** in the Hunter Exam. Each **Phase** is a guardian who
enforces a **Vow** (an input-validation rule). Every guardian's Vow has a
loophole. Clear a phase and the next one unlocks — everything beyond stays
"classified" (locked), exactly like the R6 lab's mission gating.

Phases are colour-keyed to the six Nen categories (thematic + visual identity):

| Phase | Hunter Exam location | Nen category (theme colour) | Topic cluster |
|------:|----------------------|-----------------------------|---------------|
| 1 | Written Exam | **Enhancement** (crimson) — raw fundamentals | SQLi fundamentals + the 4 core techniques |
| 2 | Trick Tower | **Transmutation** (violet) — bending the rule's shape | Testing methodology + SQLMap + header/CVE labs |
| 3 | Greed Island | **Specialization** (gold) — Greed Island is Specialist territory | OOB + Second-order |
| 4 | Hunter Association HQ | **Manipulation** (green) — "hacking the spiritual firewall" | NoSQL + LDAP |
| 5 | Chimera Ant Palace | **Conjuration** (indigo) — hidden conjured structures | ORM + XML/XXE |
| Finals | The Exam Finals | **Emission** (cyan) — projecting the full skill | Two chained multi-vuln CTFs |

---

## 3. Challenge roster (the whole lab)

Naming mirrors the R6 lab: each challenge has a code, an HxH-flavoured name, the
real vuln, and the notes section it satisfies.

### Phase 1 — The Written Exam · *SQLi Fundamentals + 4 techniques*
| # | Name | Vuln | Notes §|
|---|------|------|--------|
| 1.1 | **Gate of Trust** | SQLi auth-bypass fundamentals (`' OR '1'='1' -- `), string vs integer probing, `'` first-probe, DBMS fingerprinting by error | §2, §3, §4 |
| 1.2 | **Netero's Recipe Vault** | **Error-based** extraction (`extractvalue`, error leaks data) | §5A |
| 1.3 | **Exam Results Board** | **Union-based** extraction (`ORDER BY`, column count, `UNION SELECT`, `information_schema`) | §5B |
| 1.4 | **Trick Tower — Silent Room** | **Boolean-blind** (`AND 1=1` vs `1=2`, `SUBSTRING` walk) | §5C |
| 1.5 | **Zevil Island Medical Bay** | **Time-blind** (`IF(...,SLEEP(5),0)`, timing inference) | §5D |

### Phase 2 — Trick Tower · *Testing methodology + SQLMap*
| # | Name | Vuln | Notes §|
|---|------|------|--------|
| 2.1 | **Automated Floor Skip** | SQLMap end-to-end (`-r request.txt`, `--dbs → --dump`, `--technique`, `--level/--risk` tuning) | §6 |
| 2.2 | **A Sealed Floor — Ancient Vuln** | A GeniX-CMS-style known-CVE SQLi (CVE-2015-3933 flavour) exploited with SQLMap | §6 |
| 2.3 | **The Disguised Examiner** | **SQLi in the `User-Agent` header** (needs `--level 3` / a marked header) | §4, §6 |

### Phase 3 — Greed Island · *Advanced SQLi*
| # | Name | Vuln | Notes §|
|---|------|------|--------|
| 3.1 | **The Spell Card (GI→Outside)** | **Out-of-Band** exfil — DB triggers a callback to a bundled collaborator that captures & displays the data | §7 (OOB) |
| 3.2 | **The Cursed Card** | **Second-order / stored** SQLi — payload stored benign on registration, executes later in an admin/report query | §7 (2nd-order) |

### Phase 4 — Hunter Association HQ · *NoSQL + LDAP*
| # | Name | Vuln | Notes §|
|---|------|------|--------|
| 4.1 | **Archive — Basic Records Room** | MongoDB basics + **NoSQL operator injection** for data access (`$gt`,`$regex` blind extraction) | §8 |
| 4.2 | **Bypassing the Archive Guardian** | **NoSQL auth bypass** (`$ne`, `param[$ne]=1`, JSON body operators) | §8 |
| 4.3 | **Zodiac Twelve Directory Breach** | **LDAP injection** — auth bypass (`*)(uid=*`) + directory dump (`*)(objectClass=*`) against real OpenLDAP | §9 |

### Phase 5 — Chimera Ant Palace · *ORM + XML/XXE*
| # | Name | Vuln | Notes §|
|---|------|------|--------|
| 5.1 | **Manipulator's Firewall** | **ORM injection** — raw string into a SQLAlchemy `filter()` → real SQLi through the ORM | §10 |
| 5.2 | **Palace Blueprint Tampering** | **XML (tag) injection** — inject tags/metachars to change parsed structure/role | §11 |
| 5.3 | **The King's Sealed Archives** | **XXE** — external-entity file read (`file:///etc/passwd`), SSRF variant, blind/OOB DTD | §11 |

### Finals — The Exam Finals · *chained, multi-vuln*
| # | Name | Vuln | Notes §|
|---|------|------|--------|
| F.1 | **Trick Tower Final Exam** (BookHaven) | One target requiring **all four SQLi styles in sequence** (error → union → boolean → time) to descend the final floor | §5 |
| F.2 | **Chairman Election Infiltration** (OmniGrid) | **Four factions, four engines**: Onboarding=MySQL SQLi · Mobile API=Mongo NoSQL · Directory=LDAP · Document import=XML/XXE — chain all four to seize the Chairman seat | §5,§8,§9,§11 |

**18 challenges total** (16 phase challenges across Phases 1–5, plus the 2
Finals), covering 100% of the notes. §1 (Injection Overview) and §3 (Types taxonomy) are
taught as the **onboarding primer** on the hub + reinforced across `DEBRIEF.md`s.

---

## 4. Notes → challenge traceability matrix

| Notes section | Covered by |
|---|---|
| §1 Injection Overview | Hub onboarding primer + every debrief's "root cause" |
| §2 SQLi Fundamentals | 1.1 |
| §3 Types & Subtypes | 1.2–1.5 (one per subtype) + hub taxonomy card |
| §4 Hunting & Testing (int vs string, fingerprint, headers) | 1.1 (probing/fingerprint), 2.3 (headers) |
| §5A Error-based | 1.2 |
| §5B Union-based | 1.3 |
| §5C Boolean-blind | 1.4 |
| §5D Time-blind | 1.5 |
| §5 Methodology (9-step) | 2.1 + F.1 |
| §6 SQLMap (options, level/risk, UA, CVE) | 2.1, 2.2, 2.3 |
| §7 OOB | 3.1 |
| §7 Second-order | 3.2 |
| §8 NoSQL | 4.1, 4.2, F.2 |
| §9 LDAP | 4.3, F.2 |
| §10 ORM | 5.1 |
| §11 XML injection | 5.2, F.2 |
| §11 XXE | 5.3, F.2 |

No gaps.

---

## 5. Architecture

### 5.1 One portal, real engines
A single **Flask** portal app (matching the R6 lab convention) serves the hub +
every challenge UI and talks to real backend engines. Everything runs under one
`docker-compose.yml`.

```
                    ┌────────────────────────────────────────────┐
                    │            Flask portal (app.py)            │
  browser ──────►   │  hub · phase unlock · all challenge routes  │
                    └───┬───────┬──────────┬──────────┬───────────┘
                        │       │          │          │
                 ┌──────▼─┐  ┌──▼────┐  ┌──▼─────┐  ┌─▼───────────┐
                 │MariaDB │  │Mongo  │  │OpenLDAP│  │lxml (in-proc)│
                 │(SQL,   │  │(NoSQL)│  │(slapd) │  │  XML/XXE     │
                 │ ORM,   │  └───────┘  └────────┘  └──────────────┘
                 │ OOB,   │        ┌───────────────┐
                 │ 2nd-ord)│  ◄────►│ collaborator  │  (OOB DNS/HTTP capture)
                 └────────┘        └───────────────┘
```

- **MariaDB** — Phases 1, 2, 3, 5.1 (ORM), F.1, F.2-onboarding. Genuine MySQL
  dialect so `extractvalue`, `information_schema`, `SLEEP`, `UNION` all work as
  the notes describe. SQLi sinks are raw f-string concatenation on purpose.
- **MongoDB** — 4.1, 4.2, F.2-mobile. App builds queries from raw request objects
  so `$ne`/`$regex` operator injection is genuine.
- **OpenLDAP (slapd)** — 4.3, F.2-directory. Seeded LDIF (Zodiac Twelve DIT).
  Filters built by string concatenation → real LDAP injection.
- **lxml** in-process — 5.2, 5.3, F.2-document. Parser configured with
  `resolve_entities=True`, `no_network=False`, DTD loading on → **genuine XXE**
  (real `file:///etc/passwd` read from inside the container).
- **collaborator** — small bundled service (DNS + HTTP sink) so **OOB is
  self-contained**: the DB/app callback lands here and the UI shows the captured
  exfil. (No reliance on dnslog.cn / Burp Collaborator.) OOB firing mechanism to
  be pinned by a short spike at Phase 3 (candidate: a MySQL/PostgreSQL path that
  genuinely emits an outbound request in-container, or an app-side SSRF-style
  channel that faithfully models `LOAD_FILE`/`UTL_HTTP`). The teaching payload
  and the capture UX are fixed regardless of the exact emitter.

### 5.2 Progressive unlock
`session["cleared"]` set of phase/challenge ids (same idea as R6 `app.py`). Each
challenge sets a **flag** (`SEIYAKU{...}`) on solve; submitting the flag on the
hub unlocks the next node and fires the victory screen. Flags validated
server-side.

### 5.3 Reset & seeding
`seed/` SQL + LDIF + Mongo JS re-provision every engine idempotently on
`docker compose up`. A `/reset` route per challenge restores tampered state
(needed for second-order / stored challenges).

---

## 6. Design system (frontend)

- **Tailwind** (local build or Play CDN — it's a localhost app, CSP not a
  concern) + a custom **Nen aura** layer: per-phase accent colour, animated aura
  glow (CSS conic/radial gradients + blur), "Ren" pulse on primary actions,
  glassmorphic cards, a monospaced "exam terminal" panel for payloads/responses.
- Google Fonts: a bold display face for headings + a mono face for the terminal.
- The **frontend-design** skill is consulted at build time so this doesn't read
  as a Tailwind default template — bespoke aura palette, custom card treatment,
  hand-tuned motion.
- **Hub**: applicant terminal — phase map (locked/cleared states), the
  onboarding primer (§1 overview + §3 taxonomy as interactive cards), flag
  submission, progress.
- **Victory screen**: full-screen takeover — embedded winning gif (from the
  asset slot) layered under original Nen-aura burst animation + flag reveal +
  "next phase unlocked." Original animation is the shipped default so it works
  with zero assets present.

---

## 7. Documentation deliverables

Mirrors the R6 lab's doc model exactly.

- **`README.md`** (root) — badges, hero, the arc premise, phase table, "which doc
  do you want?" router, build/run instructions, **Legal / Disclaimer**.
- **Per-phase `README.md`** (`phase1/README.md` … `finals/README.md`) — phase
  index, rules of engagement, links to each challenge's `CHALLENGER.md`.
  **No spoilers.**
- **Per-challenge `CHALLENGER.md`** — the blackbox briefing: story, target URL,
  objective, the flag format, allowed tools. No solution.
- **Per-challenge `DEBRIEF.md`** — the teaching doc (spoilers): plain-language
  root cause, the vulnerable code walkthrough, **HxH analogy** to simplify,
  full step-by-step solve with real payloads, remediation (the notes' fixes),
  and a self-check. May include an optional `solver.py`/`solver.sh`.
- **Global `DEBRIEF` index** and a **traceability appendix** so a learner can go
  topic → challenge → debrief.

---

## 8. Repo layout

```
seiyaku-arc/
  app.py                     # Flask portal + all challenge routes
  requirements.txt
  docker-compose.yml         # flask + mariadb + mongo + openldap + collaborator
  Dockerfile                 # flask app image
  seed/                      # mariadb/*.sql, mongo/*.js, ldap/*.ldif
  collaborator/              # OOB DNS+HTTP capture service
  templates/                 # base.html, hub.html, per-challenge + victory pages
  static/                    # css (nen aura), js, img/ (victory gif slots + fetch script)
  assets/                    # documented gif drop location + fetch-assets.sh
  phase1/ … phase5/ finals/  # README.md + <chal>/CHALLENGER.md + DEBRIEF.md
  docs/                      # hero, spec, traceability appendix
  README.md  LICENSE  NOTICE
```

---

## 9. Legal / IP pack (the part that protects the author)

The honest, defensible posture — same as the R6 lab, strengthened:

1. **`LICENSE` — MIT**, © abdullah.kilani4702@gmail.com, covering **only** the
   original source, markup, docs, and written challenge content authored here.
2. **`LICENSE` scope note + `NOTICE`** — explicitly state that Hunter × Hunter
   names, characters, imagery, and the **embedded victory gifs** are **not**
   covered, are the property of their respective rights holders (Yoshihiro
   Togashi / Shueisha / the anime production committee), and are used here
   **unofficially** for non-commercial educational/parody theming. Character
   *names* are nominative/fair-use references; **the embedded gif frames are
   third-party copyrighted media the author has chosen to include and are not
   licensed by this project.**
3. **README disclaimer**: "Unofficial fan project. Not affiliated with,
   endorsed by, or sponsored by the rights holders. For local, authorized,
   educational use only."
4. **Anti-copying of the original work**: MIT already requires the copyright
   notice be retained; the README states the original lab design, code, and
   writing are the author's and must keep attribution.
5. **Honest risk statement** (in README): a licence cannot grant rights the
   author doesn't hold; embedding copyrighted gifs is a residual risk the author
   has accepted. The original-animation default + asset-slot design keeps the
   distributed repo clean if the author later chooses to ship without them.
6. **Ethics banner**: authorized/local use only (carried on the hub + README).

> Plain statement for the author, in the README: *no licence you write can stop
> the HxH rights holders, because you don't own their art — the only real
> protections are (a) not distributing their copyrighted frames and (b) the
> unofficial-fan disclaimer. This lab gives you both the safe default (original
> animations) and, at your explicit choice, the gif slots.*

---

## 10. Implementation order (phase-by-phase, checkpoint after each)

0. **Scaffold**: repo, compose, base template + Nen design system, hub with
   onboarding primer + unlock engine, victory component, LICENSE/NOTICE/README
   shell. → checkpoint.
1. **Phase 1** (1.1–1.5) + phase README + each CHALLENGER/DEBRIEF. → checkpoint.
2. **Phase 2** (2.1–2.3). → checkpoint.
3. **Phase 3** (3.1–3.2) incl. OOB collaborator + OOB-emitter spike. → checkpoint.
4. **Phase 4** (4.1–4.3) incl. Mongo + OpenLDAP services. → checkpoint.
5. **Phase 5** (5.1–5.3) incl. ORM + lxml XXE. → checkpoint.
6. **Finals** (F.1, F.2). → checkpoint.
7. **Polish**: root README, traceability appendix, hero, asset fetch script,
   full run-through verification. → done.

Each checkpoint: challenge works against the real engine, flag flow + victory
screen fire, CHALLENGER/DEBRIEF written, phase README updated.

---

## 11. Testing / verification per challenge

- **Solvable**: the documented payload in `DEBRIEF.md` actually yields the flag
  against the running stack (verified, not assumed).
- **Gated**: the next node stays locked until the correct flag is submitted.
- **Real**: exploit hits the real engine (e.g. `information_schema` really
  enumerates, `SLEEP(5)` really delays, `file:///etc/passwd` really returns).
- **Reset**: stored/second-order state can be restored.
- **Docs match code**: payloads in the debrief match the actual sink.

---

## 12. Open detail to pin during build (not blocking)

- Exact **OOB emitter** for 3.1 (spike in Phase 3). The teaching content and the
  collaborator capture UX are fixed; only the emitter mechanism is TBD.
- Whether Tailwind is CDN vs a tiny local build (decide at scaffold; leaning
  local build for offline Kali use).
