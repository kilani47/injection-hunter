# Trick Tower Final Exam

**The Exam Finals** &middot; BookHaven &middot; the final locked floor

## Briefing

You've made it to BookHaven's last floor. It isn't guarded by one lock —
it's four, stacked one after another, and each door asks a completely
different kind of question. What makes this floor the "final" one isn't
that any single door is harder than what you've already broken through.
It's that every door's key lives sealed inside the door before it, and
there is no way to skip ahead. You cannot reach the fourth lock by any
means except genuinely opening the first three, in order.

## Objective

Descend all four floors of BookHaven's final exam and recover what's
sealed behind the fourth door. Each stage's key unlocks the next stage's
door — literally, as a `token` parameter that stage requires before it
will even listen to anything else you send it.

## Targets

```
GET /f/bookhaven/stage1   (id)
GET /f/bookhaven/stage2   (token, q)
GET /f/bookhaven/stage3   (token, code)
GET /f/bookhaven/stage4   (token, id)
```

Start at `/f/bookhaven` (or Stage 1 directly). Each stage's page tells
you plainly whether your `token` was accepted.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

Submit it on the hub (`/hub`) — this is the last node in the arc.

## Allowed tools

A browser, `curl`, your own scripts, `sqlmap`, and reading the lab's own
source are all fair game — this is a whitebox-friendly exam. No source
code, hints, or tooling are off-limits.

## Hints, if you want them

- Four stages, four different SQLi techniques — in the same order you
  met them back in the Written Exam. If a stage's door won't budge with
  the technique you're trying, it's very likely asking for a different
  one.
- Stage 1 needs no key at all to start. Whatever it leaks *is* the key
  the next door wants.
- A `token` that's missing or wrong doesn't just fail a stage's real
  question — it stops that stage's vulnerable query from running at
  all. There's no way to reach a later stage's injection surface without
  the real key from the one before it.
- Nothing about any individual stage's bug is new. Each one is,
  deliberately, the exact same shape as a floor you already solved
  earlier in this arc.

No further hints here — see `DEBRIEF.md` only once you're done, or well
and truly stuck.
