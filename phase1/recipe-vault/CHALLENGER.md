# Netero's Recipe Vault

**Phase 1, The Written Exam** &middot; Floor 2 &middot; Enhancement

## Briefing

The old Chairman likes to boast that his reflexes never miss, that a
strike aimed at him arrives too late to matter, because he's already
somewhere else. He runs his recipe vault the same way: fast, public,
open to anyone who wants to look something up by number. He's confident
enough in the booth's speed that he never worried about what a *failed*
lookup might give away.

Something moving at full speed, even in failure, still leaves a trace of
what it was carrying.

## Objective

Read the vault's hidden `secret` field for one of its recipes, without
ever being handed a row that actually contains it.

## Target

```
/p1/recipe?id=<value>
```

A single lookup box: give it a recipe id, get back a name (or nothing).

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

## Allowed tools

Anything you like: a browser, `curl`, Burp, your own scripts. Reading the
lab's own source is not off-limits, this is a whitebox-friendly exam.
What matters is understanding *why* a failed lookup can still hand you
data, not just that it did.

## Hints, if you want them

- The booth doesn't just say "found" or "not found", read what it says
  when the lookup breaks entirely.
- A database that's willing to describe its own error in detail is
  sometimes willing to describe more than the error.

No further hints here, see `DEBRIEF.md` only once you're done, or well
and truly stuck.
