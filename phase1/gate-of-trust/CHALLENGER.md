# Gate of Trust

**Phase 1, The Written Exam** &middot; Floor 1 &middot; Enhancement

## Briefing

The proctor's booth stands at the entrance to the written exam hall. A vow
was sworn over its door long before you arrived: *"Only an applicant whose
name and password appear together on the roster may pass."* The examiner
running the booth trusts that vow completely, they never wrote down what
happens if an applicant's name isn't really a name at all.

Somewhere behind that gate sits the exam administrator's own terminal,
still logged in from the last roster check.

## Objective

Walk through the Gate of Trust **as the administrator**, without ever
knowing the administrator's real password.

## Target

```
/p1/gate
```

A single login form: username + password.

## Flag format

```
SEIYAKU{lowercase_snake_words}
```

The flag appears on the gate's own admin panel once you're through, submit
it on the hub to unlock the next floor.

## Allowed tools

Anything you like: a browser, `curl`, Burp, your own scripts. Reading the
lab's own source is not off-limits, this is a whitebox-friendly exam. What
matters is that you understand *why* the door opened, not just that it did.

## Hints, if you want them

- The booth doesn't just say yes or no, read what it says when it's
  confused.
- A vow that says "the name and password must match" can be reworded by
  whoever's filling in the blanks.

No further hints here, see `DEBRIEF.md` only once you're done, or well and
truly stuck.
