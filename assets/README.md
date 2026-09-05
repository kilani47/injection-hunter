# Victory GIF asset slot (optional, author-filled)

The Seiyaku Arc ships with a fully working victory screen out of the box —
an **original CSS "Nen-burst" animation** (see `templates/victory.html` /
`static/css/src/input.css` `.burst-ring`). No image or video asset is
required, none is downloaded by any build step, and none is committed to
this repository.

If you (the operator, running this locally for your own use) want to layer
a Hunter × Hunter victory clip behind the burst animation for a given node,
you may manually drop a GIF at:

```
static/img/victory/<node-id>.gif
```

where `<node-id>` is one of the 18 challenge ids from `core/unlock.py`
(`p1_1`, `p1_2`, … `p5_3`, `f1`, `f2`). `templates/victory.html` checks for
that exact filename and layers it under the burst animation automatically
when present; otherwise it falls back to the animation alone.

## This is on you, not the build

- `assets/fetch-assets.sh` is a **template** you fill in yourself with URLs
  you personally have the rights/permission to use, or that you accept the
  residual risk of using per `NOTICE`. It ships with **no real URLs** — every
  entry is a placeholder for you to replace.
- Nothing in this repo's Dockerfile, docker-compose, CI, or Python code
  fetches or bundles Hunter × Hunter media. `static/img/victory/*.gif` is
  git-ignored (see `.gitignore`) specifically so a clone of this repo never
  carries third-party frames unless you deliberately add and commit them
  yourself.
- Read `NOTICE` before doing this — embedding copyrighted frames is a real,
  separate risk from the MIT-licensed code in this repo, and no license file
  changes that.

## Recommended format

- Short (2–4s) looping GIF, ideally ≤ 2 MB so the victory screen stays snappy
  over localhost.
- Keep the aspect ratio roughly square-ish to landscape; the victory layout
  centers and caps it at `max-h-[70vh]`.
