# The Hall of Cells

**Phase 2, Trick Tower** &middot; Floor 6 &middot; Transmutation

## Briefing

Every inspection of every cell, on every floor, going back further than
anyone still on staff can remember, gets logged in one hall of
record-keeping. Most of it is exactly as dull as it sounds: routine
notes, mundane bookkeeping, dozens of tables nobody thinks twice about.
Somewhere in the noise, one entry isn't routine at all.

## Objective

Find the one record that matters, without reading every table in this
hall or every row in the largest one by hand.

## Target

```
/p2/hall?id=<value>
```

A record lookup: give it an id, get back one inspection log entry.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

## Allowed tools

Same as every floor in this phase: **sqlmap** is the intended tool, and
nothing here is off-limits. This floor isn't about finding the injection,
that part is exactly as easy as it's been on earlier floors. It's about
what you do once you're in and the database turns out to be bigger than
you expected.

## Hints, if you want them

- Getting in is the easy part. The real question is where to look once
  you're in, this database has more than one table, and the one that
  matters has a lot more rows than the others.
- Before dumping an entire table, it's worth asking how big it actually
  is, and whether there's a way to search for the *column* you care about
  without opening every table to check.
- Once you know which column and roughly what makes the interesting row
  different from the rest, sqlmap can pull out just that, instead of
  everything.

See `DEBRIEF.md` only once you're done, or well and truly stuck.
