# Zodiac Twelve Directory Breach

**Phase 4 — Hunter Association HQ** &middot; Floor 3 (final) &middot; Manipulation

## Briefing

Past the archive, past the guardian, sits the Association's most rigid
structure: the Zodiac Twelve's own membership directory. Thirteen seats
— twelve committee members, and the chairman above them — each with
exactly one entry, exactly one uid, no duplicates, no exceptions. This
directory doesn't answer vague questions the way the archive downstairs
does. Ask it for a member by name, and it tells you about that one
member. Try to sign in, and it either recognizes you as somebody real,
or it doesn't.

The Zodiac Twelve pride themselves on that rigidity — a hierarchy where
every seat is accounted for, and nothing is ever ambiguous about who's
who. That rigidity is exactly what you're here to test.

## Objective

The chairman holds something in their own directory record that no
ordinary lookup of the chairman's entry — however direct — ever shows
you. Get past this directory's sign-in, and/or get it to hand you more
of its roster than a single, well-formed lookup ever should, and find
it.

## Target

```
GET  /p4/zodiac?uid=<uid>
POST /p4/zodiac         (username, password)
```

A directory console with two features: look a member up by uid, or sign
in as one. Send `Accept: application/json` on either request for a
compact JSON answer instead of the HTML page.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

Submit it on the hub (`/hub`) to unlock the next floor.

## Allowed tools

A browser, `curl`, your own scripts, and reading the lab's own source
are all fair game — this is a whitebox-friendly exam. No source code,
hints, or tooling are off-limits.

## Hints, if you want them

- This directory isn't Mongo, and it isn't MariaDB. It's a real LDAP
  directory, and LDAP search filters are their own small string
  grammar with their own handful of special characters — not the same
  ones SQL or Mongo care about.
- If a search or sign-in form only ever expects plain names, plain
  uids, plain passwords, ask what one of those special characters does
  to the *shape* of the question being asked underneath, if it's never
  stripped or escaped out first.
- A single character can sometimes turn "does this field equal exactly
  this" into "does this field exist at all, with any value" — no need
  to know or guess a real value at all.
- A pair of characters can sometimes close a clause early and open a
  brand new one of your own right after it — while leaving the whole
  filter still perfectly well-formed underneath.
- The directory's own sign-in doesn't require you to already know
  somebody's real password. Neither does its lookup require you to
  already know exactly how many entries a search is "supposed" to
  return.

No further hints here — see `DEBRIEF.md` only once you're done, or well
and truly stuck.
