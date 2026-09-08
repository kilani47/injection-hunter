# The Cursed Card

**Phase 3 — Greed Island** &middot; Card 2 &middot; Specialization

## Briefing

Some Greed Island cards are cursed: they do nothing at all the moment
they're drawn, filed, or added to a deck. They sit there, inert, entirely
unremarkable — until a *later* round, played by someone who never touched
the round they were written in, wakes them up. The curse was always there.
It just wasn't the round it was waiting for.

The card desk on this floor works the same way. Inscribing a card is
completely uneventful — you'll get a plain confirmation, the card gets
filed into the deck alongside everyone else's, and nothing about that
response will ever tell you anything went wrong. Because nothing does. Not
yet.

## Objective

Get something you store *now* to have an effect *later* — on a query you
never sent, never typed a single character of, and don't control the
timing of. The desk that files your card away is not where this floor gets
solved. Somewhere else on this page, a *different* process looks back at
what's already sitting in the deck and treats it as trustworthy.

## Target

```
GET  /p3/cursedcard              — the console: current deck + inscribe form
POST /p3/cursedcard/inscribe     — file a new card into the deck
GET  /p3/cursedcard/report       — the appraiser re-checks the deck
GET  /p3/cursedcard/reset        — wipe the deck back to its two starting cards
```

The inscribe desk takes an `owner` and an `inscription` and files them
away. Nothing you send it changes what comes back — no error text, no row
count, nothing that varies with what you inscribe. Whatever you send it,
it looks safe, because inscribing itself genuinely is.

The appraiser report is a separate button entirely, on the same page. It
takes no input from you at all — it just re-checks whatever's already in
the deck. Pay attention to *what*, exactly, it re-checks, and *how*.

If you make a mess of the deck, `/p3/cursedcard/reset` puts it back the
way it started, no restart required.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

The flag lives on a card that isn't in this deck at all — get the
appraiser to surface it anyway, then submit it on the hub (`/hub`) to
unlock the next floor.

## Allowed tools

A browser, `curl`, your own scripts, and reading the lab's own source are
all fair game — this is a whitebox-friendly exam. No source code, hints,
or tooling are off-limits.

## Hints, if you want them

- The inscribe desk really is safe. Don't spend your time trying to break
  it directly — that's not where this floor's flaw lives.
- Ask yourself: after a card is filed away, what *else* in this app ever
  looks at it again? The appraiser report is the only other thing on this
  page that reads from the same table the inscribe desk writes to.
- If a request never carries the text you're interested in, but a
  *previous, unrelated* request could have planted that text somewhere the
  later request reads from — that's the shape to be looking for.
- This floor's earlier sibling (`p3_1`, if you've cleared it) hid its flag
  behind a query with a matching column shape, reachable via a `UNION
  SELECT`. The technique here rhymes with that one. What's different is
  *when* and *where* your input actually reaches a query.

No further hints here — see `DEBRIEF.md` only once you're done, or well
and truly stuck.
