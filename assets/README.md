# Image asset slots (optional, operator-filled)

The Seiyaku Arc ships fully working with zero image assets: the victory
screen falls back to an **original CSS "Nen-burst" animation** (see
`templates/victory.html` / `static/css/src/input.css`'s `.burst-ring`), and
every hero section that expects key art falls back to a plain themed panel
when the file is missing. Nothing is downloaded by any build step, and
none of the files below are committed to this repository.

If you (the operator, running this locally for your own use) want to add
Hunter × Hunter art for the full visual experience, drop files at these
paths. Each one is optional and independent: a missing file just falls
back to the built-in look for that spot.

| Slot | Path | Used by |
|---|---|---|
| Site icon | `static/img/favicon.png` | every page (`<link rel="icon">` in `templates/base.html`) |
| Entrance hero | `static/img/entrance.png` | `/` (`templates/index.html`) |
| Phase splash | `static/img/phase<N>.png` (e.g. `phase1.png`) | `/phase/<id>` (`templates/phase.html`) |
| Challenge wallpaper | `static/img/<template-name>.png` (e.g. `p1_gate.png` for `templates/p1_gate.html`) | that challenge's own page |
| Victory clip | `static/img/victory/<node-id>.gif` | the victory screen for that node |

A challenge wallpaper's filename matches its template's own name (the
part before `.html`), checked at render time with the `has_hero(name)`
Jinja helper (`app.py`) so dropping a new image in is enough on its own:
no route or config change needed. Victory clips instead key off the
internal challenge id from `core/unlock.py` (`p1_1`, `p1_2`, ... `p5_3`,
`f1`, `f2`), since `templates/victory.html` only ever has that id to work
with. `templates/victory.html` layers a matching gif under the burst
animation automatically when present; the challenge and phase templates
render their image when it exists and a themed text panel otherwise.

## This is on you, not the build

- `assets/fetch-assets.sh` is a **template** you fill in yourself with URLs
  you personally have the rights or permission to use, or that you accept
  the residual risk of using per `NOTICE`. It ships with no real URLs:
  every entry is a placeholder for you to replace.
- Nothing in this repo's Dockerfile, docker-compose, CI, or Python code
  fetches or bundles Hunter × Hunter media. Every path in the table above
  is git-ignored (see `.gitignore`) specifically so a clone of this repo
  never carries third-party art unless you deliberately add and commit it
  yourself.
- Read `NOTICE` before adding any of these files: embedding copyrighted
  frames or fan art is a real, separate risk from the MIT-licensed code in
  this repo, and no license file changes that.

## Recommended format

- Victory gifs: short (2 to 4 seconds), looping, ideally 2 MB or under so
  the victory screen stays snappy over localhost. Roughly square to
  landscape; the layout centers and caps it at `max-h-[70vh]`.
- Hero and wallpaper images: landscape, at least 1280 pixels wide. They
  render with `object-fit: cover` (entrance, challenge wallpapers) or
  `object-fit: contain` (phase splashes, since those already carry their
  own baked-in framing and title text), so a wider image gives the layout
  more room to crop gracefully at narrow viewports.
