# Zevil Island Medical Bay

**Phase 1 — The Written Exam** &middot; Floor 5 &middot; Enhancement

## Briefing

Zevil Island's second phase runs its own quiet Vow: nothing that happens
inside the medical bay is ever supposed to leave a visible trace. Submit
a patient id at the front desk and the terminal logs exactly one line —
"status checked" — and nothing else. Not the name. Not the chart. Not
whether the id you gave even belonged to anyone. Ask about a patient who
exists, ask about one who doesn't, ask something that isn't even a
well-formed question — the desk answers every one of them with the
identical acknowledgment, in the identical voice.

The Silent Room, a floor below, at least admitted to one of two answers.
This desk admits to nothing. If it's hiding anything at all, it isn't
going to say so — not in words, not in a different shape of page, not in
an error, not in anything you can read.

## Objective

Recover a secret this bay was never built to reveal — using nothing that
appears anywhere in its response. If there's a signal here at all, it
isn't in what comes back.

## Target

```
/p1/medbay?id=<value>
```

A single field: submit a patient id, get back one fixed acknowledgment.
Every response, for every input, looks the same.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

Submit the recovered value on the hub (`/hub`) to unlock the next floor —
and, since this is the exam's last floor, the next phase.

## Allowed tools

Anything you like: a browser, `curl`, Burp, your own scripts — but this
floor is flatly impossible to solve by eye. If the page never changes,
eyeballing responses tells you nothing; you'll need to actually measure
something about each request, and you'll want a script doing the
measuring and the asking, not a human doing either by hand. Reading the
lab's own source is not off-limits either — this is a whitebox-friendly
exam. What matters is understanding *why* a page that literally never
changes can still be made to answer questions, not just running someone
else's script against it.

## Hints, if you want them

- If a response's *content* can't tell you anything, ask what else a
  server can tell you without meaning to. A request has to actually run
  before the response comes back — and "how long that took" is
  information too, even when the page itself is silent.
- Before you try to read anything hidden, first prove to yourself you can
  make one specific request come back *slow*, and another come back
  *fast*, on purpose, using only the id field. If you can control that
  reliably, you have a lever — and it should not matter at all whether
  the underlying query was well-formed or broken.
- A database can be asked to pause for a while, but only conditionally —
  "wait N seconds, but only if this is true." Fold a question you
  actually care about into that condition, and the wait itself becomes
  the answer.

No further hints here — see `DEBRIEF.md` only once you're done, or well
and truly stuck.
