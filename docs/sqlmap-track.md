# Phase 2 SQLMap Track: beginner to professional

Phase 2 (Trick Tower) is the lab's SQLMap and testing-methodology phase:
a complete beginner-to-professional sqlmap curriculum across seven built
floors. Each floor is built so the approach that cleared the previous
floor is no longer enough, which forces one new sqlmap capability to be
learned to pass.

Every floor keeps the lab's existing conventions: its own isolated MariaDB
database (`seiyaku_<key>`) reached through its own restricted user
(`svc_<key>`), a deliberately vulnerable Flask route, an HxH-themed page, a
real working solver that drives sqlmap end to end, and a spoiler-free
CHALLENGER plus a full DEBRIEF.

## The progression

### Revision note

The track originally started with a separate `p2_1, Automated Floor Skip`
floor teaching the core workflow, followed by `p2_2, A Sealed Floor`
teaching the identical workflow again under a CVE/legacy-code narrative.
Once both existed side by side it was obvious the second taught nothing
the first hadn't: same sink shape, same sqlmap commands, same enumeration
chain. Rather than ship two floors for one lesson, `p2_1` was retired and
its foundational content (the "New to sqlmap? Read this once" flag-by-flag
primer, the `--ignore-stdin` gotcha, the `--technique`/`--level`/`--risk`
deep dive) was merged into `p2_2`'s own debrief, which kept its CVE
narrative and became the track's first floor. Every later floor's debrief
points back to A Sealed Floor's debrief for these shared explanations.
Displayed floor numbers below reflect this: A Sealed Floor is Floor 1.

### Already built (beginner rungs)

- **p2_2, A Sealed Floor** (`/p2/sealed`, key `p2_sealed`), Floor 1: the
  core sqlmap workflow (`-r` / `-u`, `--batch`, `--dbs -> --tables ->
  --columns -> --dump`, all four techniques auto-detected) taught
  alongside a CVE/legacy-code recognition narrative. Holds the shared
  "New to sqlmap" primer every later floor references.
- **p2_3, The Disguised Examiner** (`/p2/examiner`, key `p2_examiner`),
  Floor 2: header injection, the `*` custom injection marker and
  `--level`.
- **p2_4, The Warden's Ledger** (`/p2/ledger`, key `p2_ledger`), Floor 3:
  capturing and replaying a real, authenticated request (`-r`, `--data`,
  `--cookie`). The injectable lookup is a POST field only reachable with a
  valid session cookie; an unauthenticated probe sees only the login gate.
- **p2_5, The Echo Chamber** (`/p2/echo`, key `p2_echo`), Floor 4:
  defining the true/false oracle yourself (`--technique`, `--string`,
  `--time-sec`) when a deliberately noisy response defeats sqlmap's
  default detection.
- **p2_6, The Warded Door** (`/p2/warded`, key `p2_warded`), Floor 5:
  getting past a narrow WAF signature (`--random-agent`, `--tamper`). The
  filter blocks sqlmap's default User-Agent and the literal phrase
  "union select"; verified live that boolean/error-based already slip
  through with just `--random-agent`, while forcing UNION specifically
  needs `--tamper=space2comment` too, an honest lesson that WAF rules are
  usually narrow, not comprehensive.
- **p2_7, The Hall of Cells** (`/p2/hall`, key `p2_hall`), Floor 6:
  targeted enumeration and DBMS recon instead of dumping everything
  (`--search`, `--count`, `-C`, `--where`, `--current-user`, `--is-dba`,
  `--privileges`). Sixteen tables, one large (`cell_records`, 401 rows),
  the flag in one row's `secret` column. Verified live: a full boolean-blind
  dump extrapolates to ~45 minutes; the targeted extraction (same forced
  technique) takes 4.4 seconds.
- **p2_8, The Groundskeeper's Keys** (`/p2/keys`, key `p2_keys`), Floor 7:
  post-exploitation via an over-privileged account (`--file-read`,
  `--sql-shell`, `--is-dba`). No hidden table this time; the flag is a
  file on the container's own filesystem, reachable only because this
  floor's DB user, uniquely in this lab, also holds the global `FILE`
  privilege (`GRANT FILE ON *.*`, which cannot be scoped to one database
  the way every other grant here is). `secure_file_priv` confines file
  I/O to one directory at the SQL level; that same directory is also
  bind-mounted read-only from the host, an independent OS-level layer,
  verified live that `--file-write` fails because of it even though the
  SQL grant alone would permit it. `--is-dba` verified live as `False`:
  `FILE` grants host-file access, not administrative control, and it
  does not widen table access, cross-database reads are still denied.
  `--os-shell` is explained (not shipped): it needs a writable,
  web-servable destination, which this lab deliberately doesn't provide.

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
