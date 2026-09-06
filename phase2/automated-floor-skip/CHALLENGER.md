# Automated Floor Skip

**Phase 2 — Trick Tower** &middot; Floor 1 &middot; Transmutation

## Briefing

Trick Tower is built on one assumption: applicants climb it one floor at
a time, testing each rule by hand, exactly as slowly as a person tests
things. Every floor here enforces its own little rule about what an
`id` is allowed to look like — and every one of those rules was written
by someone who never imagined a tool that could test all of them, on
every floor, in the time it takes to read this sentence.

Somewhere below floor 200, sealed off from the public catalog, sits a
floor the tower was never supposed to let anyone reach on foot.

## Objective

Don't climb the tower one floor at a time. Automate past it — and reach
what's sealed behind the floors the catalog was built to show you.

## Target

```
/p2/floors?id=<value>
```

A floor catalog: give it a number, get back that floor's entry. Leave it
blank and it lists everything it's willing to show you on its own.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

The flag lives in a table the catalog never shows on its own — surface it
and submit it on the hub (`/hub`) to unlock the next floor.

## Allowed tools

This floor is built specifically to reward the right tool for the job:
**sqlmap**. Point it at the target, let it do the enumeration a human
would do far more slowly by hand, and follow it down to whatever it
finds. A browser, `curl`, or your own scripts all still work too — this
isn't a trick question, it's a genuinely easy detection for any working
scanner. Reading the lab's own source is not off-limits either — this is
a whitebox-friendly exam.

## Hints, if you want them

- The `id` field takes a plain number with nothing quoting it. That's not
  an accident, and it's exactly the shape a scanner's default checks are
  built to try first.
- You don't need to hand-craft a payload to find this one. You need to
  point a scanner at it, read what it tells you, and then keep asking it
  for more — which database, which tables, which columns, which rows.
- If you've never run `sqlmap` end-to-end before: request -> databases ->
  tables -> columns -> dump is the whole shape of it. Nothing about this
  floor requires tuning past its defaults.

No further hints here — see `DEBRIEF.md` only once you're done, or well
and truly stuck.
