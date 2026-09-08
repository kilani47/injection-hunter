# Bypassing the Archive Guardian

**Phase 4 — Hunter Association HQ** &middot; Floor 2 &middot; Manipulation

## Briefing

Deeper in the archive than the front desk sits a second door, staffed by
something the Association calls the Archive Guardian. It doesn't answer
search questions the way the records room clerk does. It checks one
thing, and one thing only: did a username and a password both show up.
If they did, and they belong to somebody, the Guardian steps aside and
whatever agent those credentials belong to is who you are now — console,
identity, clearance, all of it.

The Guardian has never once been wrong about *whether* a username and a
password showed up. It has also never once asked what kind of thing
"showed up" actually means.

## Objective

Get past the Guardian's login and into the console behind it — without
ever knowing a single real agent's actual password.

## Target

```
POST /p4/guardian
```

A sign-in form: give it `username` and `password`, get back either an
agent console (on a match) or a rejection. Send
`Accept: application/json` for a compact JSON answer instead of the HTML
page.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

Submit it on the hub (`/hub`) to unlock the next floor.

## Allowed tools

A browser, `curl`, your own scripts, and reading the lab's own source are
all fair game — this is a whitebox-friendly exam. No source code, hints,
or tooling are off-limits.

## Hints, if you want them

- Guessing a real agent's password is not the intended path, and you
  don't need to try.
- The Guardian checks that `username` and `password` were *supplied*. It
  never checks what *kind* of value each one actually is before handing
  both off to whatever it uses to look agents up.
- If your login form normally sends two flat strings, ask what happens
  if one of those fields arrives shaped like something with more
  structure than a string instead — as a nested field in a JSON body, or
  as bracket-notation keys in a form-encoded body.
- A password field that's supposed to check "does this equal the real
  password" can sometimes be persuaded to check something else instead —
  something almost always true.

No further hints here — see `DEBRIEF.md` only once you're done, or well
and truly stuck.
