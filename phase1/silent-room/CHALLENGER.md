# Trick Tower — Silent Room

**Phase 1 — The Written Exam** &middot; Floor 4 &middot; Enhancement

## Briefing

Before Trick Tower ever tests a Hunter applicant's strength, it tests
their patience. Gon once played a game like this with Kite: guess what's
sealed inside a sequence of unmarked candle-boxes, using nothing but
yes-or-no questions, no matter how the box was actually arranged inside.
No candle is ever shown. No hint is given about *why* an answer came back
wrong. The game only ever gives one bit back per question — and if you
ask something the game doesn't understand, it still just says no,
exactly the same "no" as an honest wrong guess.

The Silent Room's door works the same way. Present it a code and it
answers in exactly one of two words, in the same voice every time — never
an error, never a hint, never anything shaped differently depending on
what you asked. A wrong guess and a broken guess sound identical to it.

## Objective

The door is hiding something it will never volunteer directly. Recover it
anyway — using nothing but the door's yes/no answers, one careful
question at a time.

## Target

```
/p1/silent?code=<value>
```

A single field: present a code, get back exactly one word.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

Submit the recovered value on the hub (`/hub`) to unlock the next floor.

## Allowed tools

Anything you like: a browser, `curl`, Burp, your own scripts — but this
floor is genuinely tedious to solve one request at a time by hand.
Writing a small script that asks the door many questions in a row is
expected, not a workaround. Reading the lab's own source is not off-limits
either — this is a whitebox-friendly exam. What matters is understanding
*why* a door that never explains itself can still be made to talk, not
just running someone else's script against it.

## Hints, if you want them

- The door only ever has two answers. That's not a limitation — treat
  every question you ask it as a single bit of information, and start
  thinking about how many bits you'd need to pin down one character out
  of an unknown-length secret.
- Before you try to read anything hidden, first prove to yourself that
  you can make the door say each of its two answers *on demand*, using
  only the code field. If you can force both answers reliably, you have
  a lever — and a broken guess should never feel different from an
  honest wrong one.
- A comparison doesn't have to check for equality to be useful. Databases
  can answer "is this bigger or smaller than X?" just as easily as "is
  this exactly X?" — and that kind of question narrows things down a lot
  faster than guessing one exact value at a time.

No further hints here — see `DEBRIEF.md` only once you're done, or well
and truly stuck.
