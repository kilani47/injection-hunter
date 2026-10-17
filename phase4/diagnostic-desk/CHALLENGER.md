# The Diagnostic Desk

**Phase 4, Hunter Association HQ** &middot; Floor 2 &middot; Manipulation

## Briefing

Somewhere behind the Records Room's front desk sits a second console,
meant for staff, used for debugging the front desk's own failed
searches. Whoever built it made one choice the front desk never did:
when a query goes wrong, this console doesn't hide it. Whatever the
database itself says about a broken or malformed question, this
console repeats back, word for word.

Every incident report filed here, sealed ones included, carries an
internal tag under the field `archive_key`, the same convention this
archive uses everywhere. Nobody expected a debugging tool to be the
place that tag got read back out loud.

## Objective

Find out what the archive actually says about `archive_key` when it
can't parse what you've handed it. A console that explains its own
mistakes in enough detail is a console that was never supposed to
answer the question you're about to ask it.

## Target

```
GET /p4/diagnostics?field=<field>&value=<value>
POST /p4/diagnostics   (JSON body: {"field": "...", "value": ...})
```

Same request shape as the Records Room you may already have solved.
Send `Accept: application/json` for a compact JSON answer.

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

- If you've already solved the Records Room, you know this console's
  request shape. What's different here isn't the sink, it's what
  happens when the query you send is one MongoDB itself can't make
  sense of.
- Try sending an operator name that doesn't exist. Watch what comes
  back, closely.
- `field` is exactly as unchecked as `value` here. MongoDB has a
  top-level operator that lets a query express "does this computed
  expression hold", and that operator has its own family of type-
  conversion helpers, ones that are not shy about explaining exactly
  why a conversion failed.

No further hints here, see `DEBRIEF.md` only once you're done, or well
and truly stuck.
