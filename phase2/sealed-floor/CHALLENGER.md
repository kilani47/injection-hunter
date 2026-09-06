# A Sealed Floor

**Phase 2 — Trick Tower** &middot; Floor 2 &middot; Transmutation

## Briefing

Below the floors every applicant is shown, the tower keeps running older
things it never bothered to decommission. One of them is a small news
bulletin board — the kind of module a tower administrator wires up once,
forgets about, and never opens again once the announcements stop
mattering. It still answers requests. Nobody has looked at how it
answers them in a very long time.

Whatever sealed this floor off wasn't a new trap built to stop you. It's
an old one, left over from whoever built the module in the first place,
that nobody has come back to fix.

## Objective

Find the old weakness this bulletin board was built with, and use it to
reach the admin login it was never supposed to expose.

## Target

```
/p2/sealed?page=news&id=<value>
```

A bulletin board: give it a post number, get back that post. There's
also a static `page=about` / `page=contact` if you want to look around
first — the board itself is the part worth paying attention to.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

The flag lives in a login table this bulletin board's own display page
never mentions — surface it and submit it on the hub (`/hub`) to unlock
the next floor.

## Allowed tools

Same as every floor in this phase: **sqlmap** is the intended tool, and
nothing here is off-limits — a browser, `curl`, your own scripts, and
reading the lab's own source are all fair game. This is a whitebox-
friendly exam.

## Hints, if you want them

- This isn't a brand-new trick. It's the same shape of bug that's shown
  up, publicly, in more than one real content-management system that
  stopped getting patched — an old, unauthenticated module, addressed by
  a page name and a record number in the URL, that nobody revisited once
  "the right way to write this query" became common knowledge.
- If a target *looks* dated — an old-fashioned URL shape, a page that
  reads like nobody's touched it in years — that's worth treating as a
  signal, not decoration.
- The workflow is the same one from the last floor: point sqlmap at the
  `id` parameter, let it confirm, then enumerate downward. The table
  worth reading is not the one this page displays by default.

No further hints here — see `DEBRIEF.md` only once you're done, or well
and truly stuck.
