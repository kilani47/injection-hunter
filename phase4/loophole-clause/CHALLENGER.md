# The Loophole Clause

**Phase 4, Hunter Association HQ** &middot; Floor 4 &middot; Manipulation

## Briefing

An applicant-vetting console logs every codename lookup "for review."
It never tells you anything else, no match, no error, no hint that
anything went wrong, win or lose, the same three words come back every
time. You've already learned that MongoDB's operators have names, and
that a dict in the wrong place can smuggle one in. This desk's
rulebook runs deeper than that: underneath the operators, there's
still a sentence, written in a language with its own quotes to break.

One applicant was never meant to clear vetting at all, filed under the
codename `ghost`. Whatever note earned them that filing sits in a
field called `clearance_note`, a field this console's own lookups
never print, never list, and never explain.

## Objective

Something is logged here, every time, whether or not it was ever
supposed to happen. Find a way to make that something take
noticeably longer when a hidden condition is true than when it's
false, and you have a channel this console's own silence can't close.

## Target

```
GET /p4/loophole?codename=<value>
POST /p4/loophole   (form or JSON body: {"codename": "..."})
```

A vetting console: give it a codename, get back the same generic
confirmation, always.

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

- The response is identical no matter what you send it, not a match
  indicator, not an error, not (at a glance) a delay. One of those
  three things is not actually true.
- `codename` doesn't need bracket notation or a JSON body to carry
  this floor's payload. A single quote in the right place still means
  something here.
- MongoDB's query language has one operator that doesn't take a
  literal or another operator as its value. It takes an entire
  JavaScript expression, evaluated per document, server-side. That
  expression lives inside a string, and strings can be broken out of.
  JavaScript, unlike SQL, has its own built-in function for "pause for
  a while."

No further hints here, see `DEBRIEF.md` only once you're done, or well
and truly stuck.
