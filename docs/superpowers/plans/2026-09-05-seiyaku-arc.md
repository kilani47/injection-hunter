# The Seiyaku Arc — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-site, deliberately-vulnerable, Hunter × Hunter-themed CTF lab ("The Seiyaku Arc") that teaches every injection class in the master notes against **real** engines, with per-challenge blackbox briefings + spoiler debriefs, progressive phase unlock, animated victory screens, and a defensible legal pack.

**Architecture:** One Flask portal (`app.py`) serves the hub + every challenge UI and talks to real backends — MariaDB (SQLi/ORM/OOB/2nd-order), MongoDB (NoSQL), OpenLDAP (LDAP), in-process `lxml` (XML/XXE) — plus a bundled OOB collaborator. All orchestrated by `docker-compose`. Progressive unlock via `session["cleared"]`; each challenge emits a `SEIYAKU{...}` flag that gates the next node and fires a victory screen. This mirrors the author's existing `r6s-auth-lab` conventions.

**Tech Stack:** Python 3 / Flask, MariaDB, MongoDB (pymongo), OpenLDAP (python-ldap), lxml, Tailwind (local build), Jinja2, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-09-05-seiyaku-arc-design.md`

## Global Constraints

- **Never mention "eWPTX"** or any course/vendor name anywhere in code, docs, or UI.
- **Flag format:** `SEIYAKU{<lowercase_snake_words>}`, unique per challenge, validated server-side.
- **Real engines only** — no faked query results. Payloads from the notes must work verbatim (e.g. `extractvalue`, `information_schema`, `SLEEP(5)`, `$ne`, `*)(uid=*`, `file:///etc/passwd`).
- **Deliberately vulnerable** sinks use raw string concatenation on purpose; each vulnerable line carries a `# VULN:` comment.
- **Local/authorized use only** — ethics banner on hub + README; no internet-facing deploy.
- **Legal:** MIT covers only original code/writing; HxH names/imagery/gifs are unlicensed third-party property used unofficially. Shipped default victory visual is **original** animation; embedded gifs are an opt-in asset slot the author fills (a `fetch-assets.sh` with author-supplied URLs), never committed by the build.
- **No co-author trailer** on commits (author preference: never add `Co-Authored-By: Claude`).
- **Per-phase Nen colour keys:** P1 Enhancement=crimson `#e5484d`, P2 Transmutation=violet `#8b5cf6`, P3 Specialization=gold `#f5c518`, P4 Manipulation=green `#22c55e`, P5 Conjuration=indigo `#6366f1`, Finals Emission=cyan `#22d3ee`.
- **Doc model:** every challenge ships `CHALLENGER.md` (no spoilers) + `DEBRIEF.md` (spoilers, with an HxH analogy). Every phase ships `README.md` (no spoilers).

---

## File Structure

- `app.py` — Flask portal: hub, unlock engine, flag validation, and all challenge blueprints registered here (challenge logic in `challenges/` modules).
- `challenges/__init__.py`, `challenges/phase1.py` … `challenges/phase5.py`, `challenges/finals.py` — one Blueprint module per phase; keeps `app.py` small.
- `core/unlock.py` — progress/unlock + flag registry (single source of truth for flags & ordering).
- `core/db.py` — connection helpers (MariaDB, Mongo, LDAP) reading env from compose.
- `core/xml_parser.py` — the intentionally XXE-enabled lxml parser.
- `collaborator/collaborator.py` — OOB DNS+HTTP capture service (own container).
- `seed/mariadb/*.sql`, `seed/mongo/*.js`, `seed/ldap/*.ldif` — idempotent provisioning.
- `templates/base.html`, `templates/hub.html`, `templates/victory.html`, `templates/<chal>.html`.
- `static/css/nen.css` (compiled Tailwind + aura layer), `static/js/*`, `static/img/` (victory slots).
- `assets/fetch-assets.sh`, `assets/README.md` — documented gif drop location.
- `phase1/README.md` … `finals/README.md`; `phaseN/<chal>/CHALLENGER.md` + `DEBRIEF.md`.
- `docker-compose.yml`, `Dockerfile`, `requirements.txt`, `README.md`, `LICENSE`, `NOTICE`, `docs/traceability.md`.

**Test model:** each challenge has a `solvers/<chal>.sh` (or `.py`) — the canonical exploit. A challenge is "done" when its solver yields the flag against the running stack AND the next node stays locked until that flag is submitted. Solvers double as the failing-test-first artifact and ship as part of the debrief.

---

## Task 0: Scaffold — portal, design system, unlock engine, victory, legal shell

**Files:**
- Create: `requirements.txt`, `Dockerfile`, `docker-compose.yml`, `app.py`, `core/unlock.py`, `core/db.py`, `templates/base.html`, `templates/hub.html`, `templates/victory.html`, `static/css/nen.css`, `static/js/hub.js`, `LICENSE`, `NOTICE`, `README.md` (shell), `assets/README.md`, `assets/fetch-assets.sh`
- Test: `solvers/smoke.sh`

**Interfaces:**
- Produces: `core/unlock.py` → `NODES` (ordered list of `{id, phase, name, path, flag, built}`), `is_unlocked(session, node_id) -> bool`, `submit_flag(session, flag) -> node_or_None`, `progress(session) -> dict`.
- Produces: `core/db.py` → `mysql_conn()`, `mongo_db()`, `ldap_conn()` reading `MARIADB_*/MONGO_*/LDAP_*` env.
- Produces: `render_victory(node)` helper + `templates/victory.html` (embeds `static/img/victory/<id>.gif` if present, else original CSS Nen-burst).
- Consumes: nothing (first task).

- [ ] **Step 1 — Write the smoke solver (failing test).** `solvers/smoke.sh`: `curl -s localhost:8000/ | grep -q "Seiyaku"` and `curl -s localhost:8000/hub | grep -q "Written Exam"`. Run it; expect FAIL (nothing running).
- [ ] **Step 2 — `requirements.txt`:** `flask`, `pymysql`, `pymongo`, `python-ldap`, `lxml`, `requests`.
- [ ] **Step 3 — `core/unlock.py`:** implement `NODES` seeded with all 18 node ids (built=False except node scaffolded here), and the four functions above. Flags come from a `FLAGS` dict keyed by node id. Progress stored in `session["cleared"]` (list).
- [ ] **Step 4 — `core/db.py`:** connection helpers with env defaults matching compose service names (`mariadb`, `mongo`, `openldap`).
- [ ] **Step 5 — `app.py`:** Flask app, `secret_key` (lab constant), routes `/`, `/hub`, `POST /flag` (calls `submit_flag`, on success renders victory + unlocks), `/reset`. Register phase blueprints (empty for now via try/except so app boots before phases exist).
- [ ] **Step 6 — Design system:** `templates/base.html` (Nen aura shell, per-phase accent CSS var, ethics banner, mono "exam terminal" panel component); compile Tailwind into `static/css/nen.css` with the aura layer + the 6 Nen accent classes; `templates/hub.html` = applicant terminal with the **onboarding primer** (notes §1 overview + §3 taxonomy as interactive cards), phase map with locked/cleared states, and flag submission box. Consult the frontend-design skill so this isn't a default Tailwind look.
- [ ] **Step 7 — `templates/victory.html` + `render_victory`:** full-screen takeover, original Nen-burst animation default, `<img>` gif slot layered when `static/img/victory/<id>.gif` exists, flag reveal, "next phase unlocked" CTA.
- [ ] **Step 8 — Legal shell:** `LICENSE` (MIT © abdullah.kilani4702@gmail.com + scope note from spec §9), `NOTICE` (unofficial-fan disclaimer, HxH property statement, embedded-gif residual-risk note), `README.md` shell (premise, phase table, run instructions, Legal/Disclaimer), `assets/README.md` + `assets/fetch-assets.sh` (documented slot; URLs left for the author).
- [ ] **Step 9 — `Dockerfile` + `docker-compose.yml`:** flask service on `:8000`; declare (not yet seeded) `mariadb`, `mongo`, `openldap`, `collaborator` services so later phases only add seed + wiring.
- [ ] **Step 10 — Run smoke solver.** `docker compose up -d flask && ./solvers/smoke.sh` → PASS. Hub renders, primer visible, all phases show locked except Phase 1 entry.
- [ ] **Step 11 — Commit.** `git init` if needed; `git add -A && git commit -m "feat: scaffold Seiyaku Arc portal, Nen design system, unlock engine, victory, legal pack"` (no co-author trailer).

**Checkpoint:** hub + primer + unlock + victory + legal shell working.

---

## Task 1.1: Gate of Trust — SQLi auth-bypass fundamentals (notes §2,§3,§4)

**Files:** Create `challenges/phase1.py` (blueprint + this route), `templates/p1_gate.html`, `seed/mariadb/01_gate.sql`, `phase1/README.md`, `phase1/gate-of-trust/CHALLENGER.md`, `phase1/gate-of-trust/DEBRIEF.md`, `solvers/p1_1.sh`.

**Interfaces:** Consumes `core/db.mysql_conn`, `core/unlock`. Produces node `p1_1`, flag `SEIYAKU{the_vow_was_never_sealed}`.

- [ ] **Step 1 — Solver (failing test).** `solvers/p1_1.sh`: POST login with `username=' OR '1'='1' -- ` and any password to `/p1/gate`, assert response contains the admin panel + flag. Run → FAIL.
- [ ] **Step 2 — Seed:** `seed/mariadb/01_gate.sql` creates `applicants(id,username,password,secret)` with an admin row holding the flag.
- [ ] **Step 3 — Vulnerable route** in `challenges/phase1.py`:
  ```python
  q = f"SELECT * FROM applicants WHERE username='{u}' AND password='{p}'"  # VULN: string concat
  ```
  On any returned row, render admin panel + flag. String-based; `'` breaks it, error text is shown (fingerprintable).
- [ ] **Step 4 — Template** `p1_gate.html`: login form + a themed "Vow gate" that echoes DB errors (so `'` reveals MariaDB → fingerprint).
- [ ] **Step 5 — Docs:** `CHALLENGER.md` (story: the gate trusts its own Vow; objective: enter as admin), `DEBRIEF.md` (root cause; the `'`/`' OR '1'='1' -- ` walk; string-vs-integer probing; MariaDB fingerprint by error; **HxH analogy**: a loosely-worded Vow always-true condition; remediation: parameterized queries).
- [ ] **Step 6 — Run solver → PASS**; confirm submitting the flag on hub unlocks `p1_2`, victory fires.
- [ ] **Step 7 — Commit.**

---

## Task 1.2: Netero's Recipe Vault — Error-based extraction (notes §5A)

**Files:** add route to `challenges/phase1.py`, `templates/p1_recipe.html`, `seed/mariadb/02_recipe.sql`, `phase1/recipe-vault/CHALLENGER.md` + `DEBRIEF.md`, `solvers/p1_2.sh`.

**Interfaces:** node `p1_2`, flag `SEIYAKU{100_type_error_leak}`.

- [ ] **Step 1 — Solver:** GET `/p1/recipe?id=1' AND extractvalue(1,concat(0x3a,(SELECT secret FROM vault LIMIT 1)))-- -` ; assert the flag leaks inside the DB error string. Run → FAIL.
- [ ] **Step 2 — Seed** `vault(id,name,secret)`; the flag in a `secret` an ordinary query never selects.
- [ ] **Step 3 — Vulnerable route:** builds `SELECT name FROM vault WHERE id='{id}'`; **DB errors surfaced to the page** (`# VULN: error text echoed`).
- [ ] **Step 4 — Template:** recipe lookup UI that prints backend errors verbatim.
- [ ] **Step 5 — Docs:** error-based theory, `extractvalue`/`concat(0x3a,…)`, why the error carries data; HxH analogy (Netero's speed leaks info you weren't meant to read); remediation (don't leak errors + parameterize).
- [ ] **Step 6 — Run solver → PASS; unlock `p1_3`.**
- [ ] **Step 7 — Commit.**

---

## Task 1.3: Exam Results Board — Union-based extraction (notes §5B)

**Files:** route in `phase1.py`, `templates/p1_results.html`, `seed/mariadb/03_results.sql`, `phase1/results-board/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p1_3.sh`.

**Interfaces:** node `p1_3`, flag `SEIYAKU{append_your_own_select}`.

- [ ] **Step 1 — Solver:** find columns via `' ORDER BY N-- -`, then `?q=' UNION SELECT username,password FROM staff-- -` returns the admin creds/flag from `information_schema`-discovered table. Run → FAIL.
- [ ] **Step 2 — Seed** a public `results` table (3 cols) + a hidden `staff` table holding the flag.
- [ ] **Step 3 — Vulnerable search route:** `SELECT id,name,score FROM results WHERE name LIKE '%{q}%'` (`# VULN`), results rendered in a table (union output visible).
- [ ] **Step 4 — Template:** results board table.
- [ ] **Step 5 — Docs:** column-count via `ORDER BY`, matching types with `NULL`, `information_schema.tables/columns` enumeration, `UNION SELECT` extraction; HxH analogy (Chrollo's Skill Hunter — appending stolen abilities into his own "query"); remediation.
- [ ] **Step 6 — Run solver → PASS; unlock `p1_4`.**
- [ ] **Step 7 — Commit.**

---

## Task 1.4: Trick Tower Silent Room — Boolean-blind (notes §5C)

**Files:** route in `phase1.py`, `templates/p1_silent.html`, `seed/mariadb/04_silent.sql`, `phase1/silent-room/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p1_4.py`.

**Interfaces:** node `p1_4`, flag `SEIYAKU{yes_or_no_is_enough}`.

- [ ] **Step 1 — Solver (`.py`):** boolean oracle — page shows "PASS"/"FAIL" only; script walks the admin secret char-by-char with `AND SUBSTRING((SELECT secret…),k,1)='x'`. Assert recovered string == flag. Run → FAIL.
- [ ] **Step 2 — Seed** a `door` table; a `keeper` row holding the secret flag.
- [ ] **Step 3 — Vulnerable route:** `SELECT 1 FROM door WHERE code='{c}'`; returns identical page but with a single differing token for true vs false (no data, no error).
- [ ] **Step 4 — Template:** a "silent room" that only says PASS/FAIL.
- [ ] **Step 5 — Docs:** boolean-blind theory, `1=1` vs `1=2`, `SUBSTRING` extraction loop; HxH analogy (Gon's candle-guessing — inferring from indirect yes/no signals); remediation.
- [ ] **Step 6 — Run solver → PASS; unlock `p1_5`.**
- [ ] **Step 7 — Commit.**

---

## Task 1.5: Zevil Island Medical Bay — Time-blind (notes §5D)

**Files:** route in `phase1.py`, `templates/p1_medbay.html`, `seed/mariadb/05_medbay.sql`, `phase1/medical-bay/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p1_5.py`.

**Interfaces:** node `p1_5`, flag `SEIYAKU{time_tells_all}`.

- [ ] **Step 1 — Solver (`.py`):** no visible diff at all; use `' OR IF(SUBSTRING(...)='x',SLEEP(2),0)-- -`, measure response time to extract the flag. Run → FAIL.
- [ ] **Step 2 — Seed** a `patients` table + a `records` secret holding the flag.
- [ ] **Step 3 — Vulnerable route:** `SELECT status FROM patients WHERE id='{id}'` with response identical regardless of truth (`# VULN`), so only timing leaks.
- [ ] **Step 4 — Template:** med-bay status lookup.
- [ ] **Step 5 — Docs:** time-blind theory, `IF(cond,SLEEP(5),0)`, per-DBMS sleep table, timing measurement; HxH analogy (inferring only through delay in the med-bay); remediation. Finalize `phase1/README.md` index.
- [ ] **Step 6 — Run solver → PASS; unlock Phase 2 (`p2_1`).**
- [ ] **Step 7 — Commit.**

**Checkpoint:** Phase 1 complete, all four techniques exploitable on real MariaDB.

---

## Task 2.1: Automated Floor Skip — SQLMap end-to-end (notes §6)

**Files:** `challenges/phase2.py`, `templates/p2_floors.html`, `seed/mariadb/06_floors.sql`, `phase2/README.md`, `phase2/automated-floor-skip/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p2_1.sh`.

**Interfaces:** node `p2_1`, flag `SEIYAKU{sqlmap_walks_the_floors}`.

- [ ] **Step 1 — Solver:** save a request to `req.txt`, run `sqlmap -r req.txt -p id --batch --dump -T vault_floors`; assert the flag row is dumped. Run → FAIL.
- [ ] **Step 2 — Seed** a `floors` table + a secret `vault_floors` table with the flag.
- [ ] **Step 3 — Vulnerable route:** numeric `id` param, union+boolean+time all reachable so sqlmap detects cleanly.
- [ ] **Step 4 — Template:** floor viewer.
- [ ] **Step 5 — Docs:** full sqlmap workflow (`-r`, `-p`, `--dbs → -D … --tables → --columns → --dump`), `--technique`, `--level/--risk` meaning and the danger of `--level 5 --risk 3` on real targets; HxH analogy (Trick Tower — automating the loophole to skip floors); "manual-first" discipline.
- [ ] **Step 6 — Run solver → PASS; unlock `p2_2`.**
- [ ] **Step 7 — Commit.**

---

## Task 2.2: A Sealed Floor — known-CVE SQLi (notes §6)

**Files:** route in `phase2.py`, `templates/p2_sealed.html`, `seed/mariadb/07_sealed.sql`, `phase2/sealed-floor/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p2_2.sh`.

**Interfaces:** node `p2_2`, flag `SEIYAKU{an_old_forgotten_door}`.

- [ ] **Step 1 — Solver:** reproduce a GeniX-CMS-style pre-auth SQLi (CVE-2015-3933 flavour) on a legacy-looking endpoint (e.g. `?page=news&id=`), extract admin hash → flag, via sqlmap. Run → FAIL.
- [ ] **Step 2 — Seed** a "legacy CMS" table set with an admin credential = flag.
- [ ] **Step 3 — Vulnerable route** modeled on the CVE's injectable param, old-style markup.
- [ ] **Step 4 — Template:** a deliberately dated "ancient CMS" page.
- [ ] **Step 5 — Docs:** what a CVE is, mapping a public advisory to a payload, why old/forgotten code rots; HxH analogy (a sealed floor with an ancient, forgotten weakness); remediation (patch/upgrade).
- [ ] **Step 6 — Run solver → PASS; unlock `p2_3`.**
- [ ] **Step 7 — Commit.**

---

## Task 2.3: The Disguised Examiner — User-Agent header SQLi (notes §4,§6)

**Files:** route in `phase2.py`, `templates/p2_examiner.html`, `seed/mariadb/08_examiner.sql`, `phase2/disguised-examiner/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p2_3.sh`.

**Interfaces:** node `p2_3`, flag `SEIYAKU{the_header_was_the_door}`.

- [ ] **Step 1 — Solver:** the visible form is clean; inject via `User-Agent: ' UNION SELECT …-- -` (logged into a table then reflected/queried). Also show `sqlmap -r req.txt --level 3` finding it. Assert flag. Run → FAIL.
- [ ] **Step 2 — Seed** a `visitor_log` table whose `ua` column is later queried unsafely.
- [ ] **Step 3 — Vulnerable route:** stores/queries `request.headers['User-Agent']` via concat (`# VULN`); form fields are parameterized (red herring).
- [ ] **Step 4 — Template:** an "examiner check-in" page.
- [ ] **Step 5 — Docs:** injectable non-form inputs (headers/cookies), why `--level 3` is required, marking a header in `-r`; HxH analogy (a disguised examiner — the threat isn't where you're looking); remediation. Finalize `phase2/README.md`.
- [ ] **Step 6 — Run solver → PASS; unlock Phase 3.**
- [ ] **Step 7 — Commit.**

**Checkpoint:** Phase 2 complete.

---

## Task 3.0: OOB collaborator + emitter spike

**Files:** `collaborator/collaborator.py`, `collaborator/Dockerfile`, compose wiring, `docs/oob-spike.md`.

**Interfaces:** Produces a service capturing DNS + HTTP hits at `collaborator:80`/`:53` and exposing `GET /captures` (JSON) the portal reads.

- [ ] **Step 1 — Build collaborator:** tiny HTTP server logging any request path/host + a minimal DNS responder logging queried names; `/captures` returns recent hits.
- [ ] **Step 2 — Spike the emitter (`docs/oob-spike.md`):** determine the mechanism that genuinely emits an outbound callback in-container carrying data — evaluate MariaDB options first; if Linux MariaDB can't DNS-exfil reliably, pin an alternative that still teaches OOB faithfully (a Postgres `COPY ... TO PROGRAM`/`dblink` path, or an app-level SSRF channel that models `LOAD_FILE`/`UTL_HTTP`). Record the decision. Keep the *teaching payload shape* and the capture UX constant.
- [ ] **Step 3 — Verify:** a manual trigger lands in `/captures`. Commit.

---

## Task 3.1: The Spell Card — Out-of-Band exfil (notes §7)

**Files:** `challenges/phase3.py`, `templates/p3_spellcard.html`, seed as needed, `phase3/README.md`, `phase3/spell-card/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p3_1.sh`.

**Interfaces:** node `p3_1`, flag delivered via the collaborator capture, `SEIYAKU{word_left_the_island}`.

- [ ] **Step 1 — Solver:** inject the OOB payload (per spike) so the secret is exfiltrated to `collaborator`; read it back from `/captures`; assert flag. Run → FAIL.
- [ ] **Step 2 — Wire the vulnerable emitter** from Task 3.0 into a "spell card" endpoint.
- [ ] **Step 3 — Template:** Greed-Island "spell card" console + a panel showing collaborator captures.
- [ ] **Step 4 — Docs:** when/why OOB (fully blind, egress allowed), DNS vs HTTP channels, why callbacks slip firewalls; HxH analogy (sending word off the island through a channel the Game Master doesn't watch); remediation (egress control).
- [ ] **Step 5 — Run solver → PASS; unlock `p3_2`.** Commit.

---

## Task 3.2: The Cursed Card — Second-order/stored SQLi (notes §7)

**Files:** route in `phase3.py`, `templates/p3_cursedcard.html`, `seed/mariadb/09_cursed.sql`, `phase3/cursed-card/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p3_2.sh`.

**Interfaces:** node `p3_2`, flag `SEIYAKU{dormant_until_played}`.

- [ ] **Step 1 — Solver:** register a "card name" storing a payload benignly; then trigger the **admin report** route that concatenates the stored value → payload executes and reveals the flag. Assert. Run → FAIL.
- [ ] **Step 2 — Two routes:** register (parameterized insert — stores safely) + report (`# VULN` concatenates stored name into a new query).
- [ ] **Step 3 — Template + `/reset`** to restore the table.
- [ ] **Step 4 — Docs:** second-order model (stored safe → used unsafe later), how to hunt it (inject persistent fields, then exercise every reader); HxH analogy (a cursed card, dormant until played a later round); remediation.
- [ ] **Step 5 — Run solver → PASS; unlock Phase 4.** Commit.

**Checkpoint:** Phase 3 complete, OOB genuinely self-contained.

---

## Task 4.0: Stand up MongoDB + OpenLDAP services

**Files:** compose services `mongo`, `openldap`; `seed/mongo/init.js`, `seed/ldap/zodiac.ldif`; extend `core/db.py`.

- [ ] **Step 1 — Compose:** add `mongo` (with `seed/mongo/init.js` mounted to `/docker-entrypoint-initdb.d`) and `openldap` (osixia/openldap or bitnami) loading `zodiac.ldif`.
- [ ] **Step 2 — Seed content:** Mongo `records` + `agents` collections; LDAP DIT `dc=hunterassoc,dc=org` with `ou=zodiac` entries (the Twelve) and a `uid=chairman` holding a secret.
- [ ] **Step 3 — Verify:** `mongosh` finds records; `ldapsearch -x -b dc=hunterassoc,dc=org` returns the DIT. Commit.

---

## Task 4.1: Basic Records Room — Mongo NoSQL extraction (notes §8)

**Files:** `challenges/phase4.py`, `templates/p4_records.html`, `phase4/README.md`, `phase4/records-room/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p4_1.py`.

**Interfaces:** node `p4_1`, flag `SEIYAKU{operators_not_strings}`.

- [ ] **Step 1 — Solver:** blind-extract a hidden field with `param[$regex]` one char at a time (and `$gt`) against the search endpoint. Assert flag. Run → FAIL.
- [ ] **Step 2 — Vulnerable route:** builds a Mongo query directly from `request.args`/JSON so operator objects reach `find()` (`# VULN`).
- [ ] **Step 3 — Template:** archive search.
- [ ] **Step 4 — Docs:** MongoDB/MQL basics, operator injection, `$regex` blind extraction; HxH analogy (Manipulation — reaching into the archive's own nodes); remediation (type-check inputs).
- [ ] **Step 5 — Run solver → PASS; unlock `p4_2`.** Commit.

---

## Task 4.2: Bypassing the Archive Guardian — NoSQL auth bypass (notes §8)

**Files:** route in `phase4.py`, `templates/p4_guardian.html`, `phase4/archive-guardian/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p4_2.sh`.

**Interfaces:** node `p4_2`, flag `SEIYAKU{ne_null_walks_in}`.

- [ ] **Step 1 — Solver:** POST `username[$ne]=1&password[$ne]=1` (and the JSON `{"$ne":null}` form) → logs in as the guardian, flag shown. Assert. Run → FAIL.
- [ ] **Step 2 — Vulnerable login:** `db.agents.findOne({username:username, password:password})` with raw objects (`# VULN`).
- [ ] **Step 3 — Template:** guardian login.
- [ ] **Step 4 — Docs:** `$ne`/`$gt` auth bypass, HTTP `param[$op]` vs JSON body operators; HxH analogy (bypassing the Archive Guardian by rewriting the condition it checks); remediation.
- [ ] **Step 5 — Run solver → PASS; unlock `p4_3`.** Commit.

---

## Task 4.3: Zodiac Twelve Directory Breach — LDAP injection (notes §9)

**Files:** route in `phase4.py`, `templates/p4_zodiac.html`, `phase4/zodiac-breach/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p4_3.sh`.

**Interfaces:** node `p4_3`, flag `SEIYAKU{star_closes_the_filter}`.

- [ ] **Step 1 — Solver:** auth-bypass with username `*)(uid=*` and dump the directory with `*)(objectClass=*` against real OpenLDAP; recover `uid=chairman` secret. Assert flag. Run → FAIL.
- [ ] **Step 2 — Vulnerable route:** builds `(&(uid={u})(userPassword={p}))` by concat (`# VULN`) and binds/searches real slapd.
- [ ] **Step 3 — Template:** Zodiac directory lookup/login.
- [ ] **Step 4 — Docs:** LDAP/DIT/DN/LDIF basics, filter metachars `& | ! * ( )`, auth-bypass + extraction payloads; HxH analogy (Zodiac Twelve hierarchy — a rigid directory you infiltrate); remediation (escape + bind least-priv). Finalize `phase4/README.md`.
- [ ] **Step 5 — Run solver → PASS; unlock Phase 5.** Commit.

**Checkpoint:** Phase 4 complete on real Mongo + LDAP.

---

## Task 5.1: Manipulator's Firewall — ORM injection (notes §10)

**Files:** `challenges/phase5.py` (adds SQLAlchemy over MariaDB), `templates/p5_firewall.html`, `seed/mariadb/10_orm.sql`, `phase5/README.md`, `phase5/manipulators-firewall/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p5_1.sh`. Add `sqlalchemy` to `requirements.txt`.

**Interfaces:** node `p5_1`, flag `SEIYAKU{orm_is_not_armor}`.

- [ ] **Step 1 — Solver:** login `username=admin' OR '1'='1` via the ORM endpoint → logs in as first user / leaks flag. Assert. Run → FAIL.
- [ ] **Step 2 — Vulnerable route:** SQLAlchemy with a **raw string** in `.filter(text(f"username='{u}' AND password='{p}'"))` (`# VULN`) — SQLi through the ORM.
- [ ] **Step 3 — Template:** "firewall" login.
- [ ] **Step 4 — Docs:** ORMs normally parameterize; raw/`text()/.extra()/.raw()` sinks reintroduce SQLi; test ORM apps like SQLi; HxH analogy (Manipulator-type Nen — hacking the spiritual firewall through its own control interface); remediation (bound params).
- [ ] **Step 5 — Run solver → PASS; unlock `p5_2`.** Commit.

---

## Task 5.2: Palace Blueprint Tampering — XML injection (notes §11)

**Files:** `core/xml_parser.py`, route in `phase5.py`, `templates/p5_blueprint.html`, `phase5/blueprint-tampering/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p5_2.sh`.

**Interfaces:** node `p5_2`, flag `SEIYAKU{inject_a_new_tag}`. Produces `core/xml_parser.parse(xml_bytes)` (DTD + entity resolution ON).

- [ ] **Step 1 — Solver:** submit XML where injected tags elevate a `<role>` to admin (tag/structure injection), parser accepts it → flag. Assert. Run → FAIL.
- [ ] **Step 2 — `core/xml_parser.py`:** lxml parser with `resolve_entities=True, no_network=False, load_dtd=True` (`# VULN`).
- [ ] **Step 3 — Vulnerable route** consuming user XML into a privileged action.
- [ ] **Step 4 — Docs:** XML structure/metachars, tag injection to change parsed meaning, related (XPath/XInclude/Billion-Laughs mention); HxH analogy (tampering the Palace blueprint so the guards read a structure that isn't real); remediation.
- [ ] **Step 5 — Run solver → PASS; unlock `p5_3`.** Commit.

---

## Task 5.3: The King's Sealed Archives — XXE file read (notes §11)

**Files:** route in `phase5.py`, `templates/p5_archives.html`, a seeded secret file `/opt/king/flag.txt` (via Dockerfile), `phase5/sealed-archives/CHALLENGER.md`+`DEBRIEF.md`, `solvers/p5_3.sh`.

**Interfaces:** node `p5_3`, flag = contents of the read file `SEIYAKU{external_entity_unsealed}`.

- [ ] **Step 1 — Solver:** POST XML with `<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///opt/king/flag.txt">]>` + `&xxe;` → response returns the file contents. Also demonstrate `file:///etc/passwd`. Assert flag. Run → FAIL.
- [ ] **Step 2 — Vulnerable route** parsing user XML via `core/xml_parser` and echoing an element back (reflected XXE).
- [ ] **Step 3 — Dockerfile:** drop `/opt/king/flag.txt` with the flag.
- [ ] **Step 4 — Docs:** XXE mechanics, `SYSTEM` entities, file-read + SSRF (`http://169.254.169.254`) + blind/OOB DTD variants; HxH analogy (reading the King's sealed archives beneath the visible layer); remediation (**disable DTD/external entities** — the one fix to remember). Finalize `phase5/README.md`.
- [ ] **Step 5 — Run solver → PASS; unlock Finals.** Commit.

**Checkpoint:** Phase 5 complete; genuine XXE file read verified.

---

## Task F.1: Trick Tower Final Exam (BookHaven) — chained 4-style SQLi (notes §5)

**Files:** `challenges/finals.py`, `templates/f1_bookhaven.html`, `seed/mariadb/11_bookhaven.sql`, `finals/README.md`, `finals/trick-tower-final/CHALLENGER.md`+`DEBRIEF.md`, `solvers/f1.sh`.

**Interfaces:** node `f1`, flag `SEIYAKU{all_four_styles_descend}`.

- [ ] **Step 1 — Solver:** a 4-stage chain — error-based to map, union to read a partial, boolean to narrow, time to confirm the final locked-floor key. Each stage yields the input to the next. Assert final flag. Run → FAIL.
- [ ] **Step 2 — Build the multi-endpoint target** where each SQLi style is the only one that works at its stage (forces all four).
- [ ] **Step 3 — Template:** BookHaven "final floor" narrative UI.
- [ ] **Step 4 — Docs:** the 9-step methodology applied end-to-end; HxH analogy (the tower's final locked floor demands every technique to descend); remediation recap.
- [ ] **Step 5 — Run solver → PASS; unlock `f2`.** Commit.

---

## Task F.2: Chairman Election Infiltration (OmniGrid) — 4 engines chained (notes §5,§8,§9,§11)

**Files:** route(s) in `finals.py`, `templates/f2_omnigrid.html`, seed additions across engines, `finals/chairman-election/CHALLENGER.md`+`DEBRIEF.md`, `solvers/f2.sh`.

**Interfaces:** node `f2` (final), flag `SEIYAKU{chairman_of_the_loopholes}`.

- [ ] **Step 1 — Solver:** four faction modules — Onboarding=MySQL SQLi, Mobile API=Mongo `$ne`, Directory=LDAP `*)(uid=*`, Document import=XXE — each drops one quarter of the final key; combine to seize the Chairman seat. Assert flag. Run → FAIL.
- [ ] **Step 2 — Build the four modules** reusing the phase engines; each guards one key fragment.
- [ ] **Step 3 — Template:** OmniGrid election HQ with four faction panels + the final victory (biggest Nen-burst + gif slot `f2`).
- [ ] **Step 4 — Docs:** how four vuln classes chain into one compromise; HxH analogy (four factions vying for the Chairman seat, each guarding a different system); remediation across all classes. Finalize `finals/README.md`.
- [ ] **Step 5 — Run solver → PASS; final victory screen.** Commit.

**Checkpoint:** Finals complete; full lab solvable end-to-end.

---

## Task P: Polish, traceability, full run-through

**Files:** `README.md` (full), `docs/traceability.md`, `docs/hero.*`, `assets/fetch-assets.sh` (final), any fixes.

- [ ] **Step 1 — Full run-through:** from a fresh `docker compose up`, solve every node in order using its solver; confirm each flag unlocks the next and every victory screen fires.
- [ ] **Step 2 — `docs/traceability.md`:** the notes→challenge matrix from spec §4, each row linking to the challenge's `DEBRIEF.md`.
- [ ] **Step 3 — Root `README.md`:** badges, hero, premise, full phase table, "which doc do you want?" router, run/reset instructions, **Legal/Disclaimer** (unofficial fan project; MIT scope; embedded-gif residual-risk statement in plain language), ethics banner.
- [ ] **Step 4 — Asset script + hub gif slots** documented (`assets/README.md`), original animation confirmed as default.
- [ ] **Step 5 — Final commit.**

**Done when:** every node solvable against real engines, every doc present, legal pack complete, lab boots with one command.

---

## Self-Review

- **Spec coverage:** every spec §3 challenge (1.1–5.3, F.1, F.2) has a task; §4 traceability rows all map to a task; §5 architecture (portal, real engines, collaborator, unlock, reset) covered by Tasks 0, 3.0, 4.0; §6 design system in Task 0; §7 docs produced per challenge + Task P; §9 legal in Tasks 0 + P. No gaps.
- **Placeholders:** the only deliberately-open item is the OOB **emitter mechanism**, correctly scoped as a spike (Task 3.0) with a fixed teaching payload/UX and a recorded decision — not a silent TODO.
- **Type consistency:** `core/unlock` (`NODES`, `is_unlocked`, `submit_flag`, `progress`), `core/db` (`mysql_conn`, `mongo_db`, `ldap_conn`), `core/xml_parser.parse`, node ids `p1_1…f2`, and flag strings are used consistently across tasks.
