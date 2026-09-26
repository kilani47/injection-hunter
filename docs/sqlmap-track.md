# Phase 2 SQLMap Track: beginner to professional

Phase 2 (Trick Tower) is the lab's SQLMap and testing-methodology phase.
Its first three floors already teach the basics; this document is the
design for five further floors that extend it into a complete
beginner-to-professional sqlmap curriculum. Each floor is built so the
approach that cleared the previous floor is no longer enough, which forces
one new sqlmap capability to be learned to pass.

Every floor keeps the lab's existing conventions: its own isolated MariaDB
database (`seiyaku_<key>`) reached through its own restricted user
(`svc_<key>`), a deliberately vulnerable Flask route, an HxH-themed page, a
real working solver that drives sqlmap end to end, and a spoiler-free
CHALLENGER plus a full DEBRIEF.

## The progression

### Already built (beginner rungs)

- **p2_1, Automated Floor Skip** (`/p2/floors`, key `p2_floors`): the core
  workflow, `-r` / `-u`, `--batch`, and the `--dbs -> --tables ->
  --columns -> --dump` chain. All four techniques auto-detected.
- **p2_2, A Sealed Floor** (`/p2/sealed`, key `p2_sealed`): dumping a
  hidden table sqlmap discovers for you (legacy CMS / CVE shape).
- **p2_3, The Disguised Examiner** (`/p2/examiner`, key `p2_examiner`):
  header injection, the `*` custom injection marker and `--level`.

### New floors (this design), in beginner-to-professional order

Node ids continue the phase-2 sequence (`p2_4`..`p2_8`); DB keys are
descriptive slugs, matching the existing `p2_floors`/`p2_sealed` style.

1. **p2_4, The Warden's Ledger** (key `p2_ledger`)
   - Skill: capturing and replaying a real, authenticated request.
   - Flags taught: `-r` (saved raw request), `--data` (POST body),
     `--cookie` (session).
   - Mechanic: the injectable prisoner-ledger lookup is a POST field
     (`cell_id`) that only returns data when a valid `warden_session`
     cookie is present; without it the route redirects to a login. The
     briefing gives the login credentials.
   - Why the naive approach fails: `-u ".../p2/ledger?cell_id=1"` with no
     session sees only the login redirect, sqlmap finds no injection. You
     must log in, capture the authenticated request, and hand it to sqlmap
     with `-r` (or supply `--data` + `--cookie`).
   - DB: `prisoners` (cell_id, name, status) injectable; hidden
     `warden_vault` (id, secret) holds the flag.

2. **p2_5, The Echo Chamber** (key `p2_echo`)
   - Skill: defining the true/false oracle yourself when auto-detection is
     unreliable.
   - Flags taught: `--technique`, `--string` / `--not-string` / `--code`,
     `--time-sec`.
   - Mechanic: a boolean-blind lookup whose response embeds a random nonce
     every request, so sqlmap's content-diff heuristic cannot settle on a
     stable true/false marker on its own. The only stable signal is a fixed
     phrase present on a true condition ("the chamber resonates") and
     absent on false ("only silence").
   - Why the naive approach fails: plain `sqlmap -r req.txt -p ...` cannot
     reliably tell true from false through the noise. Supplying
     `--technique=B --string="resonates"` (or `--code`) locks the oracle
     onto the real signal. A time-based path (`--technique=T --time-sec=2`)
     is documented as the alternative when no string marker exists at all.
   - DB: `chamber` lookup table; hidden `chamber_vault` (secret) flag.

3. **p2_6, The Warded Door** (key `p2_warded`)
   - Skill: getting past an input filter / WAF.
   - Flags taught: `--tamper`, `--random-agent` (and `--list-tampers`).
   - Mechanic: the route runs a small deterministic input filter that (a)
     rejects any request whose User-Agent contains "sqlmap", and (b)
     rejects request data containing the upper-case keywords `UNION` /
     `SELECT` / `SLEEP`. Both are bypassable by known tamper behaviour:
     `--random-agent` defeats (a), `--tamper=randomcase` (or
     `space2comment`) defeats (b).
   - Why the naive approach fails: default sqlmap is blocked outright (its
     default UA is filtered, and its default payloads use upper-case
     keywords). `--random-agent --tamper=randomcase` gets through.
   - DB: `gate_log` lookup; hidden `warded_vault` (secret) flag.

4. **p2_7, The Hall of Cells** (key `p2_hall`)
   - Skill: targeted enumeration and DBMS recon instead of dumping
     everything.
   - Flags taught: `--search`, `--count`, `-C`, `--where`, plus recon
     `--current-user`, `--is-dba`, `--privileges` (and where applicable
     `--users` / `--passwords`).
   - Mechanic: this floor's database holds many tables and one large table
     with many rows; dumping everything is slow and noisy. The flag sits in
     one column in one table among the many. `--search -C secret` (or by
     table name) finds where it lives; `--count` sizes a table before
     dumping; `-C` and `--where` pull only the needed slice.
   - Why the naive approach fails: `--dump-all` is impractical here (too
     large, too slow). You have to find the target first, then extract only
     it.
   - DB: ~15 filler tables plus one `cell_records` table (many rows) whose
     single flagged row is found via search + filter.

5. **p2_8, The Groundskeeper's Keys** (key `p2_keys`)
   - Skill: post-exploitation beyond reading application tables.
   - Flags taught: `--file-read`, `--file-write`, `--sql-shell` (with a
     written explanation of `--os-shell`'s real-world prerequisites, which
     a containerized DB with no web root cannot reliably satisfy, so it is
     taught conceptually rather than shipped as a fragile path).
   - Mechanic: this floor's DB user is deliberately over-privileged, it is
     granted the global `FILE` privilege. A flag file is mounted into the
     MariaDB container under `secure_file_priv`'s allowed directory
     (`/var/lib/mysql-files/groundskeeper.flag`). `--file-read` of that
     path recovers the flag via `LOAD_FILE`.
   - Isolation note: `FILE` is a global privilege in MySQL/MariaDB (it
     cannot be scoped to one database), so `svc_p2_keys` can read files the
     mysql OS user can read. It still cannot read any other challenge's
     tables, table grants remain per-database. That gap (host-file access
     without cross-table access) is exactly the over-privileged-account
     lesson this floor teaches.
   - Setup deltas beyond a normal floor: a one-line flag file committed
     under `seed/mariadb-files/`, a read-only mount of it into the mariadb
     service, an explicit `secure_file_priv` setting, and a `GRANT FILE ON
     *.*` for this floor's user in its seed.

## Build order and per-floor deliverables

Floors are built one at a time, in the order above, each fully working and
verified before the next. Per floor:

- `core/unlock.py`: add its `FLAGS`, `BLURBS`, and `NODES` entries.
- `seed/mariadb/<nn>_<slug>.sql`: its isolated database, restricted user,
  grant, and seed data.
- `challenges/phase2.py`: its deliberately vulnerable route(s).
- `templates/<key>.html`: its themed page.
- `solvers/<node>.sh`: a real solver that drives sqlmap end to end and
  asserts the flag.
- `phase2/<slug>/CHALLENGER.md` and `DEBRIEF.md`: spoiler-free briefing and
  full debrief (the debrief teaches the sqlmap flags hands-on).
- Verify with an actual sqlmap run, then commit.

## Cross-cutting notes

- **Per-challenge isolation (non-negotiable)**: every new floor lives in
  its own database with its own restricted user, granted access to nothing
  else, the same design that fixed the earlier cross-challenge leak. As
  part of each floor's verification, before it is committed, a live check
  confirms that from that floor's DB user `information_schema` shows only
  that floor's own tables and a cross-database read of another challenge's
  table is denied. Solving one floor can never surface another floor's data
  or flag. (p2_8 is the one nuance: its user additionally holds the global
  `FILE` privilege, which grants host-file access but still no other
  challenge's table access, as described above.)
- **Stacked queries (`S`)**: PyMySQL disables multiple statements per
  execute by default, so the `S` technique is not available on standard
  floors. This is realistic (many drivers do the same) and is left as-is;
  no floor depends on it.
- **Ethics**: p2_8's post-exploitation flags cross from reading reachable
  data into acting on the host. Its debrief carries the same
  authorized-use-only framing the lab uses throughout: these are for
  systems you have explicit written permission to test to that depth.
