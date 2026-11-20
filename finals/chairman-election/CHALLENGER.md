# Chairman Election Infiltration

**The Exam Finals** &middot; OmniGrid &middot; the arc's last node

## Briefing

OmniGrid is the platform running the Hunter Association's Chairman
election, four separate departments, four separate systems, each run
by a faction convinced their own corner is secure because nobody has
ever attacked it before. Onboarding runs on one database. The mobile
app talks to another. The internal directory is a third kind of system
entirely. Document intake is a fourth.

The four are chained, one behind the next. Only Onboarding stands open;
each faction you breach hands you the fragment that unlocks the one after
it, so OmniGrid falls in order, never out of turn. None of them will tell
you how it breaks, each is a kind of lock you have already picked
somewhere in this exam, wearing a different face.

The Chairman's own seat is sealed behind all four at once. No single
faction's breach opens it. You need a fragment of the seal from every
one of them.

## Objective

Breach the four OmniGrid factions in sequence, carrying each fragment
forward to open the next, then present all four together to seize the
Chairman seat.

## Targets

```
GET  /f/omnigrid/onboarding   (id)                    , MariaDB   (open)
POST /f/omnigrid/mobile       (token, username, password), MongoDB  (opened by onboarding's fragment)
GET  /f/omnigrid/directory    (token, uid)            , OpenLDAP  (opened by mobile's fragment)
POST /f/omnigrid/import       (token, xml)            , XML parser (opened by directory's fragment)
POST /f/omnigrid/seize        (onboarding, mobile, directory, document)
```

Start at `/f/omnigrid` for an overview of all four factions and the
final seize form.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

Submit it on the hub (`/hub`), this is the final node in the arc.

## Allowed tools

A browser, `curl`, your own scripts, `sqlmap`, and reading the lab's own
source are all fair game, this is a whitebox-friendly exam. No source
code, hints, or tooling are off-limits.

## Hints, if you want them

- Nothing about any individual faction's bug is new. Every one of the
  four is the exact same shape as a floor you've already broken open
  somewhere earlier in this arc, just on a fresh target, with no
  narrative pointing you at which technique it wants.
- Onboarding behaves exactly like the Written Exam's error-based floor.
- The Mobile API's login checks that a username and a password were
  supplied. It never checks what *kind* of thing "supplied" means.
- The Directory only ever shows you one entry for a well-formed,
  single-uid lookup. Ask what widening that lookup's filter, the same
  way you already have once in this arc, gets you instead.
- Document Import parses whatever XML document you send it, and echoes
  back one specific element's content once parsing finishes, including
  whatever that content resolved to.
- The factions are chained: every one after Onboarding stays sealed
  until you present the previous faction's fragment as its `token`. So
  you breach them in order, each fragment opens the next, and only then
  do all four get checked together at the seize.

No further hints here, see `DEBRIEF.md` only once you're done, or well
and truly stuck.
