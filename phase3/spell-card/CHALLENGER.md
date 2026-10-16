# The Spell Card

**Phase 3, Greed Island** &middot; Card 1 &middot; Specialization

## Briefing

Every card on Greed Island resolves the same way: you play it, the game
master reads what it does, and the field changes accordingly, but the
game master never actually tells you what happened. Win, lose, or
nothing at all, the message back to you is identical. That's not a bug
in the table rules. That's how the game master runs every card, on
purpose, for every player.

Somewhere in this deck sits a card that was never meant to be read by a
player at all, sealed away from the ordinary catalog, the way certain
cards on this island are said to be. The game master still knows what it
does. You're just never supposed to be told.

## Objective

The game master isn't the only one paying attention to what happens when
a card resolves. Get the card's true effect to travel somewhere you
*can* actually read it, a channel the game master's own reply to you
was never built to cross.

## Target

```
/p3/spellcard?card=<value>
```

A spell-card reader: give it a card id, get told only that "the card was
cast into the field." No effect text, no error, nothing that changes
based on what you asked for, every response looks the same.

There's also a small panel on that same page, and a matching
`/p3/spellcard/captures` endpoint, worth paying attention to. Nothing
about the spell-card reader's own response is where this challenge gets
solved.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

The flag lives on a card the reader's own catalog never lists, surface
its true effect and get it to travel somewhere you can actually see it,
then submit it on the hub (`/hub`) to unlock the next card.

## Allowed tools

A browser, `curl`, your own scripts, and reading the lab's own source
are all fair game, this is a whitebox-friendly exam. No source code,
hints, or tooling are off-limits.

## Lab environment note

This database build includes a custom SQL function **`http_get(url)`**
that fires a real outbound HTTP GET from inside MariaDB's own process and
returns the HTTP status code as a string (e.g. `"200"`). It stands in for
the platform-native OOB primitives that exist on other databases
(Oracle's `UTL_HTTP`, SQL Server's `xp_dirtree`) but are absent on stock
Linux MariaDB. You're expected to use it.

There is also an HTTP listener on the lab's internal network reachable
from the database as **`http://collaborator`**. In a real engagement you
would substitute your own Burp Collaborator domain or interactsh URL;
here it plays that role. Its capture feed is proxied at
`/p3/spellcard/captures` so your browser can poll it directly.

## Hints, if you want them

- The `card` field takes a plain string with nothing suggesting it's
  sanitized. If you've broken out of a quoted string context before
  (earlier floors in this exam), the shape will feel familiar.
- The response never changes, no matter what you send it, not a row,
  not an error, not a delay. That's not you missing a signal; there
  genuinely isn't one to find in the page's own HTTP response.
- You have a function that makes the database phone home, and a listener
  to receive the call. The flag lives in a table the reader's own catalog
  never touches. Put those three facts together.

No further hints here, see `DEBRIEF.md` only once you're done, or well
and truly stuck.
