# The Silent Courier

**Phase 5, Chimera Ant Palace** &middot; Floor 5 &middot; Conjuration

## Briefing

The Palace's courier service accepts dispatch orders as small XML
documents. Submit one and the desk confirms it was received — a fixed,
identical confirmation every time, regardless of what your document
contained. The desk never reads any element back to you, never confirms
any title or value from your document, never shows you anything that
was resolved during parsing.

Two floors back, the same parser's `resolve_entities=True` and
`load_dtd=True` settings turned a file read into a readable response,
because that floor's route happened to echo the resolved text. This
desk does none of that. The response tells you nothing about what the
parser did internally.

## Objective

The flag is at `/opt/king/dispatch.txt` inside the container. The desk
never serves that path and never echoes resolved entity content. What
the parser resolves stays on the server side — except that resolving
an external `SYSTEM` reference is a **network event**, and network
events leave traces that have nothing to do with this route's own
response.

Read the flag out of a channel the desk never touches.

## Target

```
POST /p5/courier
```

Body: a form field named `xml`, whose value is your entire raw XML
document. Send `Accept: application/json` for a compact JSON answer
(`{"dispatched": true}` on success, `{"error": "..."}` on bad XML).
The response is identical whether or not the parser fetched any
external resources during parsing.

## Out-of-band channel

Within the compose network, the `collaborator` service runs at
`http://collaborator`. It logs every inbound HTTP request and returns
them at `GET http://collaborator/captures`. You cannot reach
`collaborator` from your browser directly (it has no published host
port), but Flask can. The route `GET /p5/courier/captures` proxies
`collaborator`'s capture feed, so you can poll it from your browser or
from a script.

For this floor, the collaborator also exposes a ready-made external
exfil DTD:

```
GET http://collaborator/evil.dtd?f=<file-path>
```

This endpoint serves an XML DTD fragment that reads the file at
`<file-path>` and ships its contents to `collaborator`'s own capture
log via a second HTTP request. You need to make the parser fetch it.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

Submit it on the hub (`/hub`) to unlock the next floor.

## Allowed tools

A browser, `curl`, your own scripts, and reading the lab's own source
are all fair game. Reading `challenges/phase5.py`,
`collaborator/collaborator.py`, and `core/xml_parser.py` is not
cheating.

## Hints, if you want them

- The parser configuration is the same as the previous two floors:
  `load_dtd=True`, `resolve_entities=True`, `no_network=False`. What
  changed is only what the route does with the parsed result.
- An external parameter entity makes the parser fetch a URL by
  itself. Write a DOCTYPE that declares one whose `SYSTEM` identifier
  is the collaborator's `/evil.dtd?f=/opt/king/dispatch.txt` URL.
- Expanding that entity (`%remote;`) in the internal subset causes the
  parser to fetch the external DTD. The DTD's own declarations then run
  inside the parser, triggering a second network request to the
  collaborator's capture log.
- After sending the payload, poll `/p5/courier/captures`. Look for an
  entry with `path == "/exfil"` and read the `d` query parameter.

No further hints here — see `DEBRIEF.md` only once you're done, or
well and truly stuck.
