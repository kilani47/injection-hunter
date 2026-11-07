# The Royal Guard Rankings

**Phase 5, Chimera Ant Palace** &middot; Floor 4 &middot; Conjuration

## Briefing

The Palace keeps a public roster of the Royal Guard and lets any visitor
sort it however they like, by name, by division, by whichever column
they name. Every column on that roster is public; there is nothing in
it anyone is trying to hide from you.

The firewall two floors back taught you that an ORM is no protection
once a *value* reaches a raw query as hand-built text. This desk never
puts your input anywhere near a value at all. It only ever uses what
you send to decide the **order** rows come back in. Whoever built it
clearly thought that made it safe, an ordering can't leak a value it
never selects, can it?

## Objective

Nothing on this roster is secret, so there's nothing here to read the
ordinary way. But the King keeps a seal the roster desk can *reach*
without ever *showing*, and the order it hands rows back in is decided
by an expression you control. An expression can ask a question about
something the roster never displays, and the answer changes what you
do see: which guard is listed first. Read the seal.

## Target

```
GET /p5/roster?sort=<column>
```

A roster listing. Pass a sort column, get the roster back in that
order. Send `Accept: application/json` for a compact JSON answer,
including the ordered member list, instead of the HTML page.

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

- The sort column goes into the query as an **identifier**, not a value.
  A bound parameter can stand in for `'alice'`; it can never stand in
  for the bare word `name` used as a column. Ask what that means for
  whether the usual "just parameterize it" fix is even possible here.
- Try sorting by a column that doesn't exist. The error you get back is
  itself the proof that whatever you type reaches the real `ORDER BY`
  clause, not an allow-list that would have rejected it first.
- `ORDER BY` doesn't only accept a column name. It accepts an
  *expression*, including a `CASE WHEN ... THEN ... ELSE ... END`. What
  if the two branches of that CASE sorted the roster into two visibly
  different first-rows?
- If you can make "which guard is listed first" depend on whether a
  condition is true, you have a yes/no oracle. Everything else is
  asking the right yes/no questions about a value one character at a
  time, the same blind walk as the timing floor in the Hunter
  Association phase, read off row order instead of a clock.
- `ASCII()` and `SUBSTRING()` are your friends for asking about one
  character at a time, and `ASCII()` specifically sidesteps a
  case-insensitivity trap a direct `=` comparison would walk straight
  into.

No further hints here, see `DEBRIEF.md` only once you're done, or well
and truly stuck.
