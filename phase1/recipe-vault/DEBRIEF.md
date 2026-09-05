# Netero's Recipe Vault — Debrief

**Node:** `p1_2` &middot; **Flag:** `SEIYAKU{100_type_error_leak}` &middot; **Route:** `GET /p1/recipe` &middot; **Sink:** `challenges/phase1.py`, `mariadb` (`vault` table)

## Root cause

The lookup route builds its query the same way the Gate of Trust did —
raw f-string concatenation, no escaping:

```python
# challenges/phase1.py
q = f"SELECT name FROM vault WHERE id='{recipe_id}'"  # VULN: string concat
cur.execute(q)
row = cur.fetchone()
```

But this floor's real bug sits one line down, in the `except` block:

```python
except Exception as exc:
    error = str(exc)   # VULN: raw DBMS error text echoed back to the client
```

Normal SQLi extraction (like p1_1's `UNION`-free auth bypass) works by
getting the *result set* to contain what you want. Error-based extraction
is different: it never needs a working query at all. It only needs the
database to fail in a way whose error *message* contains the data. Since
this route prints `str(exc)` straight into the page, any function that
raises an exception carrying attacker-chosen text becomes an exfiltration
channel — no `UNION`, no matching column count, no working `SELECT`
required.

## The technique: `extractvalue()`

MariaDB (and MySQL) ship `extractvalue(xml_frag, xpath_expr)` — a function
meant to run an XPath query against a fragment of XML and return the
matched node. `xpath_expr` is expected to be a *valid XPath expression
string*. Handing it something that **isn't** valid XPath — like a plain
colon-prefixed string — makes `extractvalue()` throw before it ever
touches real XML, and MariaDB's error handler for that failure embeds the
first ~32 characters of the offending `xpath_expr` string directly in the
exception text: `XPATH syntax error: '<up to 32 chars here>'`.

That's the whole trick: `xpath_expr` doesn't have to be a literal — it can
be the *result of a subquery*, computed at query time. Feed it your own
`SELECT` wrapped in `concat()`, and MariaDB helpfully quotes back
whatever that subquery returned, packaged inside its own error message.

## The walk

**1. Confirm the sink is reachable and errors leak verbatim.** A bare
quote in `id` is enough:

```
/p1/recipe?id=1'
```

The page's error panel echoes the raw exception — same pattern as p1_1,
but this time it's the entire exploit surface, not just a fingerprinting
tell.

**2. Build the payload.** The working payload against this seed:

```
1' AND extractvalue(1,concat(0x3a,(SELECT secret FROM vault LIMIT 1)))-- -
```

- `1'` closes the string literal the app opened with `id='...'`.
- `AND extractvalue(1, ...)` appends a second condition to the `WHERE`
  clause. `extractvalue()`'s first argument (`1`) is a throwaway XML doc —
  it's never reached, because argument two fails to parse first.
- `concat(0x3a, (SELECT secret FROM vault LIMIT 1))` builds the "XPath
  expression" at query time: `0x3a` is a hex literal for `:` (a harmless
  separator that also makes the leaked value easy to spot in the error
  text), concatenated with the actual subquery — `SELECT secret FROM
  vault LIMIT 1`, which reads the very column the app's own `SELECT name
  FROM vault ...` never touches.
- `-- -` comments out the rest of the original query (the trailing
  `'` and anything else the app appends), so the statement still parses
  as a whole.

**3. MariaDB evaluates the subquery first**, gets back the flag string,
concatenates it after `:`, hands that to `extractvalue()` as its XPath
argument — and `extractvalue()` immediately rejects it as invalid XPath.
The resulting exception, verbatim from this exact seed and route:

```
(1105, "XPATH syntax error: ':SEIYAKU{100_type_error_leak}'")
```

The flag is short enough (well under MariaDB's ~32-character truncation
window for this error) to come through whole in a single request — no
need to binary-search or `SUBSTRING()` it out character by character, the
way blind boolean/time-based techniques would require.

**4.** `challenges/phase1.py`'s `except` block catches that exception,
stores `str(exc)` in `error`, and `templates/p1_recipe.html` prints it
verbatim in the "the vault stumbled over your query" panel. The flag is
on the page.

## HxH analogy

Isaac Netero's whole reputation rests on the idea that he's too fast to
read — by the time you've registered where his fist is, it's already
somewhere else, and you're left reacting to an attack that already
landed. But "too fast to read" and "gives away nothing" aren't the same
claim. A strike that connects, even one thrown at inhuman speed, still
displaces air, still leaves an afterimage, still tells a sufficiently
attentive opponent something about the technique that threw it — not
because the technique failed, but because *any* motion that fast still
has to interact with the world it moves through.

The vault's mistake is the same shape. It isn't naive about its main
channel — a normal lookup really does only ever hand back a `name`. But
it never considered that a lookup which *misfires* is still an
interaction with the database, and that MariaDB's own diagnostics for
that misfire are willing to narrate exactly what was being computed at
the moment it broke. The vault was never touched at its front door. It
gave up the secret in the recoil.

## Remediation

- **Parameterized queries, always** — the same fix as p1_1:

  ```python
  cur.execute("SELECT name FROM vault WHERE id=%s", (recipe_id,))
  ```

  This alone closes the injection point entirely; `extractvalue()` would
  never get attacker-controlled SQL to evaluate in the first place.
- **Never return raw DBMS exception text to the client.** This is the
  bug that actually made extraction possible here — even a leftover
  injection point is far less dangerous if a failing query just returns
  a generic "recipe not found" and logs the real exception server-side
  instead of rendering `str(exc))` to the page.
- **Least privilege on the DB account.** An app account that can only
  `SELECT` the `name` column it needs (column-level grants, or a view
  that never exposes `secret`) limits what even a successful injection
  can reach.
