# The King's Sealed Archives

**Phase 5 — Chimera Ant Palace** &middot; Floor 3 (final) &middot; Conjuration

## Briefing

Beneath the Palace sits an archive nobody outside the King's household
has ever been permitted to read. You can't browse it directly — but
there's a request desk above it that will confirm, in writing, exactly
what document title you asked it to look up. Ask for something, and it
reads your own request back to you.

That's the desk's whole feature: read back what you asked for. It has
never shown anyone anything they didn't already put in their own
request themselves — as far as the desk itself is concerned.

## Objective

The sealed archive holds a document with something in it that was never
meant to leave the King's own household. You can't ask the desk for it
by name — it isn't a title in the archive's own catalogue at all. Get
the desk to read it back to you anyway.

## Target

```
POST /p5/archives   (xml)
```

Submit a small request document as the `xml` form field. Send
`Accept: application/json` for a compact JSON answer instead of the
HTML page.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

Submit it on the hub (`/hub`) to unlock the Finals.

## Allowed tools

A browser, `curl`, your own scripts, and reading the lab's own source
are all fair game — this is a whitebox-friendly exam. No source code,
hints, or tooling are off-limits.

## Hints, if you want them

- Your request is a full XML document, not just a plain-text title —
  which means it's allowed to carry more than just the `<document>`
  element the desk actually reads.
- XML documents are allowed to declare their own local vocabulary of
  shorthand names at the very top, before the document body even
  starts — and reference one of those names anywhere inside the body
  that follows.
- One flavor of that shorthand doesn't just stand in for a fixed piece
  of text you wrote yourself. It stands in for *the contents of
  wherever you point it* — and the parser is the one that goes and
  fetches that content, not you.
- The desk only ever echoes back whatever text ends up inside the
  `<document>` element once your whole request has been fully
  processed — not what you literally typed there.
- This isn't specific to one file. If you can make the desk read back
  one file's contents this way, you can very likely make it read back
  others the app's own process has permission to open.

No further hints here — see `DEBRIEF.md` only once you're done, or well
and truly stuck.
