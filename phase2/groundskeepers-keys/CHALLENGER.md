# The Groundskeeper's Keys

**Phase 2, Trick Tower** &middot; Floor 7 &middot; Transmutation

## Briefing

The groundskeeper's task log is about as dull as this tower gets: hedges,
gravel, a hinge waiting on parts. Nothing in it is worth stealing. The
groundskeeper's own ring of keys, on the other hand, opens doors that
have nothing to do with hedges at all.

## Objective

There is no hidden table here worth dumping. Whatever you're looking
for isn't inside this database at all.

## Target

```
/p2/keys?id=<value>
```

A task-log lookup: give it an id, get back one task and its note.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

## Allowed tools

Same as every floor in this phase: **sqlmap** is the intended tool.
Getting the injection point isn't the challenge here, it's exactly as
easy as it's been on every earlier floor. The question this floor asks
is: once you have a working injection, what can this particular account
actually reach, and is it limited to this database at all?

## Hints, if you want them

- Don't assume the flag is a row in a table just because every earlier
  floor's flag was. Ask what else a database account might be allowed to
  touch.
- A database server usually has more on its filesystem than its own data
  files. sqlmap has flags for reading, and even writing, files through an
  injection point, if the account it's using has the privilege for it.
- Not every account that can do this is a full administrator. Worth
  checking what this one actually is.

See `DEBRIEF.md` only once you're done, or well and truly stuck.
