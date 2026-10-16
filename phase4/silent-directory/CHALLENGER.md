# The Silent Directory

**Phase 4, Hunter Association HQ** &middot; Floor 6 &middot; Manipulation

## Briefing

A separate desk from the Zodiac Committee's own directory, the
registrar's verification window exists for exactly one purpose: given
a uid and a note, confirm whether they match. Nothing else. Not the
record's name, not its title, not the note's real contents, win or
lose, the only thing that ever comes back is a single word: verified,
or not.

Whoever designed this believed that was enough to make it safe.

## Objective

A desk that only ever says yes or no is not the same thing as a desk
that can't be made to say something useful. Find out what "yes" and
"no" actually mean to this particular desk, and whether you can shape
a question so that the answer tells you something the desk was never
supposed to reveal.

## Target

```
POST /p4/registrar/verify
```

Form-encoded or JSON body: `uid` and `note`. The response is exactly
one boolean field, `verified`.

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

- If you've solved the Zodiac Twelve's own directory breach, you
  already know this desk's underlying grammar. What's different here
  is the response shape: there is no multi-entry dump mode to fall
  back on, ever. The yes/no answer is the entire channel.
- A single character, used as an entire field's value, means
  something very specific in this grammar: "this attribute exists, I
  don't care what it holds."
- That same character also works at the *end* of a partial value. What
  does that tell you about growing a value one confirmed piece at a
  time?

No further hints here, see `DEBRIEF.md` only once you're done, or well
and truly stuck.
