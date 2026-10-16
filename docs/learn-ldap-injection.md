# Learning notes: LDAP injection

> Read this before Phase 4, floor 3 (`zodiac-breach`). From-scratch primer:
> what LDAP is, how a search filter is built, the special characters, the
> two attack patterns (auth bypass + directory dump), the blind variant the
> lab doesn't drill, and the escaping fix. Grounded in RFC 4515/4514 and the
> OWASP Testing Guide (see **References**).

---

## 1. What LDAP is (just enough)

LDAP is a protocol for querying a **directory** — a tree of entries
(people, groups, devices). Think "a read-mostly database shaped like a
filesystem of records."

```
            dc=hunterassoc,dc=org              <- the root (base DN)
                     │
                 ou=zodiac                      <- an organizational unit
                     │
        ┌────────────┼────────────┐
   uid=rat      uid=ox      uid=chairman        <- entries (one per member)
        │
   each entry has ATTRIBUTES:
      uid: rat
      cn:  Rat Member
      userPassword: ...
      description: ...        <- the lab hides the flag here on uid=chairman
```

Key vocabulary:

- **DN (Distinguished Name):** the full path to an entry, e.g.
  `uid=chairman,ou=zodiac,dc=hunterassoc,dc=org`. (RFC 4514.)
- **Attribute:** a `name: value` pair on an entry (`uid`, `cn`, `mail`,
  `userPassword`, `description`).
- **Search filter:** the query — "find entries matching this predicate".
  This is where injection lives. (RFC 4515.)

---

## 2. The search-filter grammar (RFC 4515)

Filters are **prefix/Polish notation**, fully parenthesized. A single
comparison:

```
   (uid=rat)          attribute = value
```

Logical operators sit **in front** of their parenthesized operands:

```
   (&(a=1)(b=2))      AND   — both must hold
   (|(a=1)(b=2))      OR    — either holds
   (!(a=1))           NOT
```

So a normal two-field login filter looks like:

```
   (&(uid=rat)(userPassword=secret))
    │ │        │
    │ │        └─ clause 2
    │ └─ clause 1
    └─ AND: both clauses must match
```

Special value forms:

```
   (mail=*)             PRESENCE  — "mail attribute exists, any value"
   (cn=Ba*er)           SUBSTRING — wildcard inside a value
   (uid=*)              matches EVERY entry that has a uid
```

---

## 3. The characters that matter

These are the RFC 4515 **syntactically significant** characters. If user
input containing any of them reaches a filter *unescaped*, the input can
change the filter's structure instead of just its values:

```
   (   )   &   |   !   *   \   NUL
```

| Char | Role in a filter | Why it's dangerous unescaped |
|---|---|---|
| `(` `)` | delimit clauses | close a clause early / open a new one |
| `&` `|` | AND / OR | inject a logical operator |
| `!` | NOT | negate a clause |
| `*` | presence / wildcard | turn `attr=value` into `attr=anything` |
| `\` | escape introducer | corrupt or craft escapes |
| NUL | string terminator | truncate the filter |

> **Contrast with SQL and NoSQL:** SQLi breaks out of a *quote*; NoSQLi
> confuses a *type*; LDAPi rewrites a *filter grammar*. Different
> mechanisms, same root idea — **attacker text becomes attacker-controlled
> logic**.

---

## 4. Why string concatenation is the bug

The lab's sink builds the filter by raw f-string concatenation, escaping
nothing:

```python
# login
login_filter = f"(&(uid={username})(userPassword={password}))"   # VULN
# search
search_filter = f"(&(uid={search_uid})(objectClass=inetOrgPerson))"  # VULN
```

With an ordinary `username=rat` there are no special characters, so the
filter is exactly what was intended. The moment you include `(`, `)`, or
`*`, you are writing filter *syntax*, not just a value.

---

## 5. Pattern A — Authentication bypass (lab floor p4_3, login shape)

Template:

```
   (&(uid=<username>)(userPassword=<password>))
```

### The wildcard trick

Set the password to a bare `*`. In an equality filter, a lone `*` becomes
a **presence** assertion — "userPassword exists, with any value at all" —
which is true for every entry that has a password:

```
   username = rat
   password = *

   (&(uid=rat)(userPassword=*))
                           ^^^
            "rat has a password" -> true -> logged in as rat, no password known
```

### The clause-injection trick

Use `(` `)` to close the intended clauses and add your own always-true
one, commenting the rest out of relevance with a presence clause:

```
   username = *)(uid=*))(|(uid=*
   password = anything

   (&(uid=*)(uid=*))(|(uid=*)(userPassword=anything))
          └── matches everything ──┘
```

(The exact breakout string depends on the template; derive it by writing
the template out and making your injection produce a *well-formed* filter
that is trivially true. An unbalanced `(`/`)` is a malformed filter and
the directory simply rejects it — that rejection is itself feedback.)

```
   intended:   (&(uid=RAT)(userPassword=PW))
                     │                 │
   inject uid = *    │                 │
                     ▼                 ▼
   result:     (&(uid=*)(userPassword=PW))   -> "any uid AND pw=PW"
   inject both:
   result:     (&(uid=*)(userPassword=*))    -> matches EVERY entry
```

---

## 6. Pattern B — Directory dump (lab floor p4_3, search shape)

Template:

```
   (&(uid=<search_uid>)(objectClass=inetOrgPerson))
```

A normal `uid=rat` can match **at most one** entry, because `uid` is the
unique naming attribute. So if you can make the filter match *more than
one* entry, you've provably widened it beyond any legitimate lookup — and
the lab treats a multi-match result as a **raw dump** that reveals the
hidden `description` field (the flag on `uid=chairman`).

Breakout: close the `uid` clause, add a trivially-true presence clause,
and let the template's own trailing clause stay valid:

```
   search_uid = *)(objectClass=*

   (&(uid=*)(objectClass=*)(objectClass=inetOrgPerson))
       │        │                  │
       │        │                  └─ template's own clause, still valid
       │        └─ presence: every entry has objectClass
       └─ presence: every entry has uid
   => matches ALL twelve members + chairman => dump mode => description leaks
```

```
   one entry matched  ──►  "curated view"  (uid/cn/title/mail only)
   many entries matched ─► "raw dump view" (adds description = FLAG)
                     ▲
          only reachable by a widened (injected) filter
```

---

## 7. The gap — blind LDAP extraction (not in the lab)

When a search gives only a *boolean* (match / no-match) instead of dumping
entries, you extract a hidden attribute char-by-char with substring
filters, exactly like the NoSQL `$regex` walk:

```
   (&(uid=chairman)(userPassword=S*))    match?  yes  -> starts with S
   (&(uid=chairman)(userPassword=SE*))   match?  yes
   (&(uid=chairman)(userPassword=SEA*))  match?  no
   (&(uid=chairman)(userPassword=SEI*))  match?  yes ... grow the prefix
```

Same blind loop diagram as the NoSQL notes §5 — only the oracle grammar
differs. Worth knowing because real directories often expose exactly this
boolean shape (a login that just says yes/no).

### DN injection (a different context)

Filter injection is the common case. Separately, if user input is
concatenated into a **DN** (e.g. a bind DN or a base DN) rather than a
filter, the dangerous characters and escaping rules are different — those
are **RFC 4514** rules (`, + " \ < > ;` and leading/trailing spaces), not
RFC 4515. Different context, different escape set. The lab is filter
injection; just know DN injection is its own thing.

---

## 8. Defense (the fix)

1. **Escape every RFC 4515 metacharacter** in user input before it reaches
   a filter. python-ldap ships the helper:
   ```python
   from ldap.filter import escape_filter_chars
   f = f"(&(uid={escape_filter_chars(username)})(userPassword={escape_filter_chars(password)}))"
   ```
   The RFC 4515 escape table (hex-backslash):
   ```
     *   -> \2a        (   -> \28        )   -> \29
     \   -> \5c        NUL -> \00
   ```
   After escaping, a `*` the user typed becomes the literal text `\2a` and
   can only ever be compared as data — never interpreted as a wildcard.

2. **Don't authenticate by filter at all when you can avoid it.** The
   robust pattern is: search for the user with an escaped filter to get
   their DN, then do a **separate LDAP bind** with that DN + the supplied
   password, and let the directory verify the password. A failed bind =
   wrong password. This never compares `userPassword` inside a filter, so
   the wildcard-password trick simply can't apply.

3. **Validate input shape** (allow-list characters for a `uid`: letters,
   digits, a few punctuation — reject the rest) as defense in depth.

4. **Least privilege on the service bind account** — the app's own bind
   should be able to read only the attributes/subtree it needs, never
   `userPassword` if it doesn't need it.

---

## 9. Map to the lab

| Shape | Request | Filter built | What you practice |
|---|---|---|---|
| Directory search | `GET /p4/zodiac?uid=…` | `(&(uid=…)(objectClass=inetOrgPerson))` | dump via `*)(objectClass=*` → `description` leak |
| Login | `POST /p4/zodiac` | `(&(uid=…)(userPassword=…))` | auth bypass via `*` / clause injection |

One underlying bug (unescaped concatenation into `search_s()`), reachable
two ways. Read `challenges/phase4.py` — the two `# VULN` lines are the
`login_filter` / `search_filter` f-strings — then `zodiac-breach/DEBRIEF.md`
walks the exact payloads and shows the escaped fix.

---

## 10. References (official / primary)

- **RFC 4515 — LDAP: String Representation of Search Filters** —
  https://www.rfc-editor.org/rfc/rfc4515  (the filter grammar + the escape
  rules)
- **RFC 4514 — LDAP: String Representation of Distinguished Names** —
  https://www.rfc-editor.org/rfc/rfc4514  (DN injection context)
- **OWASP Testing Guide — Testing for LDAP Injection** (WSTG-INPV-06) —
  https://owasp.org/www-project-web-security-testing-guide/
- **OWASP Cheat Sheet — LDAP Injection Prevention** —
  https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
- **python-ldap `ldap.filter.escape_filter_chars`** —
  https://www.python-ldap.org/en/latest/reference/ldap-filter.html
