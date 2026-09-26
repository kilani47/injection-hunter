# The Echo Chamber

**Phase 2, Trick Tower** &middot; Floor 5 &middot; Transmutation

## Briefing

A resonant stone room sits partway down the tower. Whisper a word and it
answers, but never plainly: a word it holds makes the stone ring, a word it
doesn't leaves the air dead. Either way the walls throw back a fresh wash of
random resonance every single time, so no two answers ever look quite alike,
even when you ask the exact same thing twice.

The room only ever tells you one honest bit: ring, or no ring. Everything
else it shows you is noise.

## Objective

Recover the one true word the chamber keeps sealed away, using only its
ring-or-silence answer. The catch that makes this floor its own lesson: the
constant noise means an automated tool cannot reliably guess what a "yes"
looks like on its own. You have to define that for it.

## Target

```
/p2/echo?whisper=<word>
```

Whisper a word; the chamber rings or stays silent, wrapped in a random
resonance reading that changes on every request.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

## Allowed tools

Anything, and this floor is a good place to push `sqlmap` past its defaults.
The point is not a new kind of injection (it's an ordinary boolean-blind);
it's learning to steer a scanner when a noisy page defeats its automatic
true/false detection.

## Hints, if you want them

- Ask the chamber the same thing twice and compare the whole responses. A
  tool that decides "true vs false" by comparing responses will struggle
  with what you see.
- Find the one part of the answer that is stable and only appears on a
  "ring". Then tell your tool that exactly that is what "true" looks like.
  In `sqlmap` that is `--string`; `--technique` lets you force which method
  it uses, and `--time-sec` tunes the slow fallback.
- An `AND`-based test needs a request that is already "true" to flip. Point
  your tool at a word the chamber actually holds, not a nonsense one.

See `DEBRIEF.md` only once you're done, or well and truly stuck.
