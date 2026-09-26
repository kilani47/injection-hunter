# The Warden's Ledger

**Phase 2, Trick Tower** &middot; Floor 4 &middot; Transmutation

## Briefing

Deep in Trick Tower's holding block, the warden keeps a ledger of every
detained applicant. The booth's terminal will happily look up any cell by
its number, but only for someone who has already signed in at the booth. To
a stranger it shows nothing but the sign-in prompt; it won't so much as
glance at a cell number until you're logged in.

The booth's own sign-in is honest and unremarkable. The ledger lookup
behind it is not.

## Objective

Recover the warden's master pass, a value the ledger lookup was never meant
to reach. The catch that makes this floor its own lesson: the lookup only
runs for a signed-in visitor, so whatever you use to test it has to test it
as a signed-in visitor too, not from the outside.

## Target

```
/p2/ledger
```

A sign-in form. Once you're in, a second form looks up a cell by its id
(for example `A-1`).

## Credentials

The booth sign-in is not the puzzle, so you're given a working pass:

```
username: warden
password: tower-key-7
```

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

## Allowed tools

Anything: a browser, `curl`, Burp, and this floor is the right place to
reach for `sqlmap`. The point isn't finding an exotic bug; it's learning to
drive your tools against an injection that lives *behind a login*, so they
carry your session with them.

## Hints, if you want them

- Sign in first, then watch what the lookup request actually contains
  (its method, its body, and the cookie the booth handed you).
- A scanner pointed at the lookup from outside the session sees only the
  sign-in gate. Give it the request you send *after* signing in, cookie and
  all.
- With `sqlmap`, saving a full request to a file and replaying it with `-r`
  carries the cookie automatically; `--data` and `--cookie` are the manual
  equivalents.

See `DEBRIEF.md` only once you're done, or well and truly stuck.
