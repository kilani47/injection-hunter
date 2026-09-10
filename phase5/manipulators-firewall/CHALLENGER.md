# Manipulator's Firewall

**Phase 5, Chimera Ant Palace** &middot; Floor 1 &middot; Conjuration

## Briefing

The Palace's inner gate is nothing like the raw checkpoints you've
broken through so far. This one was built properly: a real
object-relational layer sits between the gate and the database behind
it, translating every ordinary sign-in into safely parameterized SQL
the way a modern framework is supposed to. Whoever built it clearly
knew what they were doing, most of the time.

Frameworks like this one usually give developers an escape hatch for
the rare query their normal API can't express cleanly. Escape hatches
are exactly that: hatches. If whoever built this gate ever reached for
one and fed it a string assembled by hand instead of trusting the
framework's own safe query builder, the "properly built" gate is
carrying the exact same weakness the raw checkpoints did, it's just
one layer further back.

## Objective

The chairman's own staff record holds something no ordinary,
well-formed sign-in into this gate ever shows you, not even a
correctly-credentialed one for a different account. Get into the
chairman's own session without their real password, and find it.

## Target

```
POST /p5/firewall   (username, password)
```

A staff sign-in form. Accepts a form body or a JSON body. Send
`Accept: application/json` for a compact JSON answer instead of the
HTML page.

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

- The gate is built on a real ORM over a real SQL database. That does
  not automatically mean every query it ever runs went through the
  ORM's own safe, parameterized query-building API.
- Every ORM worth using ships an escape hatch for raw SQL, for the rare
  case its normal API can't express. An escape hatch only stays safe if
  whoever reaches for it still avoids splicing untrusted text directly
  into the string it executes.
- If a raw SQL string was ever assembled with an f-string or `+`
  concatenation instead of the ORM's own bound-parameter syntax, ask
  what a single `'` character does to that string once it's built,
  the exact same question you've been asking since Floor 1 of the
  Written Exam.
- You do not need to know any real username or password to get in.

No further hints here, see `DEBRIEF.md` only once you're done, or well
and truly stuck.
