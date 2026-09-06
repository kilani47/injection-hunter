# The Disguised Examiner

**Phase 2 — Trick Tower** &middot; Floor 3 &middot; Transmutation

## Briefing

Every applicant who reaches this floor is met by an examiner who asks
one simple question at the door: what's your badge id? Answer it, and
the desk looks you up and tells you who it thinks you are. It's a
perfectly ordinary check-in form. It behaves exactly like it looks like
it should.

That's the whole trick. This floor's examiner isn't who — or where —
you'd expect. The threat was never sitting in the box you typed into.

## Objective

The check-in form is not the door. Something else about your visit —
something you never typed into any field — is the thing this floor is
actually trusting without question. Find it, and use it to reach
whatever the disguised examiner is really guarding.

## Target

```
GET /p2/examiner?badge_id=<value>
```

A check-in desk: give it a badge id, get back that examiner's record.
Leave it blank and you'll just see the check-in form and a small log of
recent visits.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

The flag lives in a table this floor's own check-in flow never queries
on its own — surface it and submit it on the hub (`/hub`) to unlock the
next floor.

## Allowed tools

**sqlmap** is fair game, same as every floor in this phase — but don't
assume it will find everything with its own out-of-the-box defaults.
Read what it's actually testing before deciding it's told you everything
there is to know. A browser, `curl`, your own scripts, and reading the
lab's own source are all fair game too — this is a whitebox-friendly
exam.

## Hints, if you want them

- Try the obvious thing first. Confirm it for yourself instead of taking
  it on faith either way.
- A web request carries more than whatever's in its form fields or query
  string. Everything the browser (or `curl`, or sqlmap) sends along with
  a request is still a value the server has to decide whether to trust.
- If a scanner tells you a parameter "does not appear to be injectable,"
  that's a statement about what it tested — not a statement about
  everything a request contains. Worth checking exactly what it looked
  at before moving on.
- Read sqlmap's own documentation (or `sqlmap -hh`) for what its `--level`
  option actually controls, and what it tests differently at higher
  values.

No further hints here — see `DEBRIEF.md` only once you're done, or well
and truly stuck.
