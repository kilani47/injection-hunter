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

## Why we can't just read the secret directly

On the Gate of Trust, the app displayed whichever row it found, *including
that row's `secret` column*, so simply making the right row appear was
enough. This floor is more careful. Its normal query only ever asks for the
`name` column (`SELECT name FROM vault ...`), and the page only ever prints
that `name` back. Even if you rewrite the query to fetch `secret`, the app
still renders only `name`, so the secret never reaches the screen through
the normal output. (Black-box check: send a legitimate `?id=1` and notice
the page labels what it shows as `name>`, that is the only field it will
ever display.)

So we need a different way out. Recall the second bug from the Root cause:
when a query *fails*, the app prints the database's raw error message onto
the page. That is the opening. Instead of trying to make the database
*return* the secret (it won't show us), we make the database *fail on
purpose*, in a way that stuffs the secret into the error text, and the
app's own careless "here's the error" behavior then hands it to us. This is
called **error-based** extraction: the answer rides home inside an error
message rather than inside a normal result.

## The SQL pieces, in plain terms

The payloads below are built from a few small parts. Here is each one,
plainly (the single quote `'` and the `-- ` comment were covered in the
Gate of Trust primer):

- **`extractvalue(a, b)`** is a built-in MariaDB function. Its real,
  intended job is to dig a value out of a piece of XML: argument `a` is
  some XML, argument `b` is an "XPath expression" naming which part to pull
  out. We don't actually care about XML here, we're abusing the function
  for its error behavior.

- **XPath**, in one sentence, is a tiny query language for pointing at a
  spot inside an XML document (think of it as the "address" of an item
  inside a nested structure). The only thing that matters for us:
  `extractvalue` expects argument `b` to be a *validly written* XPath
  address. Hand it something that isn't one, and it gives up and throws an
  error, and, crucially, that error message quotes back the invalid text we
  gave it (roughly the first 32 characters). That quoted-back text is our
  smuggling channel.

- **`concat(x, y, ...)`** glues strings together end to end, like `+` for
  text. We use it to stick a marker in front of whatever we're stealing, so
  `concat('~', 'FLAG')` produces `~FLAG`.

- **`0x7e`** is just the number 126 written in hexadecimal (base 16), and
  126 is the character code for a tilde `~`. So `0x7e` is a compact way to
  write the character `~` in SQL. We use `~` as a visible marker: when the
  error comes back reading `...error: '~SEIYAKU{...}'`, the `~` makes it
  obvious where our stolen value begins. It has no special power; any
  harmless marker would do. Writing it in hex also spares us from putting
  yet more quote characters inside a payload that is already juggling
  quotes.

- **a subquery**, like `(SELECT secret FROM vault LIMIT 1)`, is simply a
  second, inner query whose single result is used in place of a value.
  `LIMIT 1` means "just the first row", so the inner query returns exactly
  one value, which is what `concat`/`extractvalue` expect to receive.

- **`database()`** returns the name of the database you're currently
  connected to (each challenge has its own; see the Isolation note at the
  end). It lets us say "only tables in *my* database" without hardcoding a
  name.

- **`information_schema`** is a database MariaDB keeps about itself: a
  built-in catalog listing every database, table, and column. Querying
  `information_schema.tables` is how you *ask the database what tables
  exist* instead of having to know their names in advance.

Put together, `extractvalue(1, concat(0x7e, (SELECT secret FROM vault LIMIT
1)))` reads as: "work out my secret, glue a `~` in front of it, then try to
treat the result as an XPath address." It isn't a valid address, so MariaDB
throws, and the error politely quotes back `~` followed by the secret.

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

**3. Don't assume the table name, ask the database for it.** Nothing so
far has named `vault`, and nothing so far requires reading the app's
source. Each challenge in this lab runs in its **own isolated database**
(see the "Isolation" note below), and the connecting user can only see
that one database's tables. So the simplest possible enumeration just
works, list the tables in your current database:

```
id=1' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name)
    FROM information_schema.tables WHERE table_schema=database())))-- -
```

```
(1105, "XPATH syntax error: '~vault'")
```

That is the whole answer: this floor's database contains exactly one
table, `vault`, and no other challenge's tables are even visible to this
connection, so the result comes back short and unambiguous. There's
nothing to guess and nothing to sift through.

(On a single shared schema this would be much messier, `group_concat`
of every table across all 18 floors would overrun `extractvalue()`'s
~32-character truncation, and a `secret` column would show up in a dozen
different tables. The per-challenge isolation is exactly what keeps this
step clean; see the Isolation note at the end.)

**4. Now extract the secret**, from the table step 3 just discovered:

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

## Isolation (why step 3 was so clean)

Every MariaDB-backed challenge in this lab runs in its **own database**
(`seiyaku_p1_recipe` here) and connects as its **own restricted user**
(`svc_p1_recipe`), granted access to nothing but that one database.
This is a deliberate design choice, and it's what keeps a challenge's
injection point from leaking anything beyond that challenge:

- `information_schema` is filtered by the connecting user's privileges,
  so from inside this floor you can only see this floor's own tables.
  Other challenges' tables (and their flags) are not merely
  unreferenced, they're invisible.
- Cross-database reads (`SELECT ... FROM seiyaku_p1_gate.applicants`) are
  denied outright, as is `USE`-ing another challenge's database.

That's why step 3's table enumeration returned a single clean answer.
It also means a solver never has to wonder whether they pulled *this*
floor's flag or accidentally wandered into another one, the database
account they're injecting through simply cannot reach anywhere else.
The tradeoff is that this floor no longer doubles as a lesson in
cross-schema enumeration; that technique belongs in an environment
that genuinely shares one schema, which this lab intentionally does not.
