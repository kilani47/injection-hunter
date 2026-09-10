# Basic Records Room

**Phase 4, Hunter Association HQ** &middot; Floor 1 &middot; Manipulation

## Briefing

The Association keeps a records archive: licenses, incident reports,
audit drafts, access logs, the ordinary paper trail of running a
Hunter organization. The front desk clerk who staffs the search
counter is helpful, in a narrow sort of way. Ask for a record by
field and value, and the clerk will tell you exactly one thing: whether
anything in the archive matched. Not what matched. Not how many, beyond
a bare count. Never the record itself.

Somewhere in that archive sits an entry that never appears on any
listing, and was never meant to be searched for by name. Every record
kept here, including that one, carries an internal tag under the
field `archive_key`, a value the front desk never prints, never lists,
and never explains. The clerk will still answer questions about it,
though, the same way it answers questions about anything else.

## Objective

Get the clerk to reveal what's sitting in `archive_key` on that hidden
record, one character at a time if that's what it takes, using
nothing but the same match/no-match answer the search counter gives
for anything else you ask it.

## Target

```
GET /p4/records?field=<field>&value=<value>
```

A search console: give it a field and a value, get back whether
anything matched. Send `Accept: application/json` for a compact JSON
answer instead of the HTML page.

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

- The clerk's answer is always the same shape, no matter what you ask:
  matched, or it didn't. That's not a limitation you need to work
  around, it's the whole channel. One bit per question is still
  enough to reconstruct a value, given enough questions.
- `value` gets compared against whatever's actually stored. Ask
  yourself what "compared" could mean beyond "is it equal to this
  exact string", and whether the search counter ever checks what
  *kind* of thing you handed it before it goes and compares that.
- If your search client normally sends flat `key=value` pairs, look at
  whether it can send something with more structure than that instead,
  nested query-string keys, or a JSON body.

No further hints here, see `DEBRIEF.md` only once you're done, or well
and truly stuck.
