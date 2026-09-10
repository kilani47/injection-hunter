# Exam Results Board

**Phase 1, The Written Exam** &middot; Floor 3 &middot; Enhancement

## Briefing

The instant a paper is graded, its score goes up on the public board, no
gatekeeping, no login, just a search box anyone can use to look up an
applicant by name. The clerk running it is proud of how flexible the
search is: type any fragment of a name and the board prints back every
row that matches.

What the clerk never stopped to think about is that the board doesn't
just print rows it *finds*. It prints rows, full stop. Chrollo Lucilfer's
Skill Hunter doesn't fight for what it steals; it simply appends a stolen
technique onto the end of his own repertoire, and from then on it's his,
indistinguishable from anything he was born with. A board that will print
back whatever a query hands it has the same problem: it never asks
whether every row it's about to display was actually supposed to be
there.

## Objective

Get the results board to display something it was never scored to show,
something that lives nowhere near the applicants' exam scores.

## Target

```
/p1/results?q=<value>
```

A single search box: type (part of) an applicant's name, get back a table
of matching rows (id / name / score).

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

The flag surfaces as ordinary-looking table content once you're through,
submit it on the hub to unlock the next floor.

## Allowed tools

Anything you like: a browser, `curl`, Burp, your own scripts. Reading the
lab's own source is not off-limits, this is a whitebox-friendly exam.
What matters is understanding *why* the board can be made to show rows it
never selected, not just that it can.

## Hints, if you want them

- The board's table always has the same number of columns. What happens
  if your search term tries to ask for a *second* table's worth of rows,
  appended right onto the first?
- Before you can append anything cleanly, you need to know exactly how
  many columns you're matching.

No further hints here, see `DEBRIEF.md` only once you're done, or well
and truly stuck.
