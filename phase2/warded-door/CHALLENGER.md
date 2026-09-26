# The Warded Door

**Phase 2, Trick Tower** &middot; Floor 5 &middot; Transmutation

## Briefing

A knock-code lookup, ordinary enough, sits behind a door carved with wards.
The wards don't examine every visitor closely; they only flare at two
specific things: a presence they already recognize by name, and a
particular combination of words spoken together in one breath. Anything
else, however strange, passes straight through unnoticed.

## Objective

Recover the ward-key hidden behind the door. The wards are real, and they
will refuse you outright if you announce yourself as something they
already know, or if you phrase your question in the one shape they've been
carved to reject.

## Target

```
/p2/warded?knock=<value>
```

A knock-code lookup, in the same shape as every earlier floor's lookup
form.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

## Allowed tools

Anything, and this floor is built specifically to be worked with `sqlmap`.
The lesson isn't a new SQL technique; it's what to do when your usual tool,
run at its defaults, gets refused outright.

## Hints, if you want them

- If every single request gets the exact same refusal, before sqlmap has
  even had a chance to test anything, the refusal probably isn't about
  your payload at all. Check what identifies *you*, not what you're
  sending.
- Once you're past that, watch closely whether every kind of question gets
  refused, or only a specific one. A ward carved to recognize one shape of
  words doesn't necessarily recognize a different phrasing of the same
  idea.
- If one specific technique's payload keeps getting refused while others
  get through, look at what makes that payload's *text* different, then
  look at what `sqlmap --tamper` scripts are for.

See `DEBRIEF.md` only once you're done, or well and truly stuck.
