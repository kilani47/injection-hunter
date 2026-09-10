# Palace Blueprint Tampering

**Phase 5, Chimera Ant Palace** &middot; Floor 2 &middot; Conjuration

## Briefing

Every visitor to the Palace walks away from the front gate with a
badge. The press that prints it works from a short blueprint: your
name goes into one slot on the blueprint, a fixed "guest" clearance
goes into the next, and the whole thing gets read back and handed to
you as your pass. Every checkpoint guard past the gate trusts that
badge completely, they never re-derive your clearance from scratch,
they just read what the blueprint says.

The press has never printed anything but a guest clearance for a guest
badge. That's not because it's incapable of printing anything else,
it's because nobody expected a visitor's *name* to be able to add new
lines to the blueprint it's inserted into.

## Objective

The King holds a clearance level of his own, and it comes with a
record no guest badge is supposed to be able to carry. Get the press to
print a badge with that clearance anyway, and read the record.

## Target

```
POST /p5/blueprint   (name)
```

A badge-printing form: give it a visitor name, get back a printed
badge. Send `Accept: application/json` for a compact JSON answer,
including the exact blueprint the press printed for your name, instead
of the HTML page.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

Submit it on the hub (`/hub`) to unlock the next floor.

## Allowed tools

A browser, `curl`, your own scripts, and reading the lab's own source
are all fair game, this is a whitebox-friendly exam. No source code,
hints, or tooling are off-limits.

## Hints, if you want them

- The badge, underneath, is a small XML document. Your name goes into
  one specific slot in it before the whole thing gets parsed.
- XML has a handful of characters that are never just "text" once
  they're inside a document: `< > & ' "`. Ask what happens if your name
  contains one of the first two.
- A single stray `<` on its own will very likely make the press choke
  and reject your badge outright, that's the parser genuinely enforcing
  that the document stays well-formed, not it being broken. A
  well-formed document that's structured differently than the blueprint's
  author intended is a completely different story.
- If your name can close the tag it was meant to sit inside of, what's
  stopping it from opening a brand new tag of its own right after,
  one the blueprint's fixed clearance line comes after, not before?

No further hints here, see `DEBRIEF.md` only once you're done, or well
and truly stuck.
