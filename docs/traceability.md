# Traceability Matrix

Every topic in the lab's source notes, mapped to the challenge(s) that
teach it. Every row below is a **built, solver-verified** node running
against a real backend engine — nothing in this matrix is aspirational.

| Notes topic | Challenge(s) | Engine | Debrief |
|---|---|---|---|
| Injection overview / trust-boundary model | Whole arc's premise (README, every `CHALLENGER.md`) | — | [`README.md`](../README.md) |
| SQL injection fundamentals — `'` probe, auth bypass | 1.1 Gate of Trust | MariaDB | [`phase1/gate-of-trust/DEBRIEF.md`](../phase1/gate-of-trust/DEBRIEF.md) |
| SQLi types — in-band / blind / OOB overview | Phase 1 as a whole (§3 of the notes maps onto floors 1.2–1.5) | MariaDB | [`phase1/README.md`](../phase1/README.md) |
| Hunting & testing — probing, DBMS fingerprinting | 1.1 Gate of Trust (error fingerprinting); 2.3 Disguised Examiner (non-form inputs) | MariaDB | [`phase1/gate-of-trust/DEBRIEF.md`](../phase1/gate-of-trust/DEBRIEF.md), [`phase2/disguised-examiner/DEBRIEF.md`](../phase2/disguised-examiner/DEBRIEF.md) |
| Error-based SQLi (`extractvalue()`) | 1.2 Netero's Recipe Vault; F.1 stage 1 | MariaDB | [`phase1/recipe-vault/DEBRIEF.md`](../phase1/recipe-vault/DEBRIEF.md) |
| Union-based SQLi (column count, `UNION SELECT`) | 1.3 Exam Results Board; F.1 stage 2 | MariaDB | [`phase1/results-board/DEBRIEF.md`](../phase1/results-board/DEBRIEF.md) |
| Boolean-blind SQLi (`AND 1=1`/`1=2`, bisection) | 1.4 Trick Tower Silent Room; F.1 stage 3 | MariaDB | [`phase1/silent-room/DEBRIEF.md`](../phase1/silent-room/DEBRIEF.md) |
| Time-blind SQLi (`IF(cond,SLEEP(n),0)`) | 1.5 Zevil Island Medical Bay; F.1 stage 4 | MariaDB | [`phase1/medical-bay/DEBRIEF.md`](../phase1/medical-bay/DEBRIEF.md) |
| The 9-step SQLi methodology, applied end-to-end | F.1 Trick Tower Final Exam | MariaDB | [`finals/trick-tower-final/DEBRIEF.md`](../finals/trick-tower-final/DEBRIEF.md) |
| SQLMap essentials (`-r`, `-p`, `--dbs`→`--dump`) | 2.1 Automated Floor Skip | MariaDB | [`phase2/automated-floor-skip/DEBRIEF.md`](../phase2/automated-floor-skip/DEBRIEF.md) |
| SQLMap against a known-CVE-style target | 2.2 A Sealed Floor | MariaDB | [`phase2/sealed-floor/DEBRIEF.md`](../phase2/sealed-floor/DEBRIEF.md) |
| SQLi via non-form inputs (`User-Agent` header, `--level 3`) | 2.3 The Disguised Examiner | MariaDB | [`phase2/disguised-examiner/DEBRIEF.md`](../phase2/disguised-examiner/DEBRIEF.md) |
| Out-of-band SQLi (DNS/HTTP exfil channel) | 3.1 The Spell Card | MariaDB + collaborator | [`phase3/spell-card/DEBRIEF.md`](../phase3/spell-card/DEBRIEF.md) |
| Second-order / stored SQLi | 3.2 The Cursed Card | MariaDB | [`phase3/cursed-card/DEBRIEF.md`](../phase3/cursed-card/DEBRIEF.md) |
| NoSQL injection — operator objects, blind extraction (`$regex`/`$gt`) | 4.1 Basic Records Room | MongoDB | [`phase4/records-room/DEBRIEF.md`](../phase4/records-room/DEBRIEF.md) |
| NoSQL auth bypass (`$ne`) | 4.2 Bypassing the Archive Guardian; F.2 Mobile API faction | MongoDB | [`phase4/archive-guardian/DEBRIEF.md`](../phase4/archive-guardian/DEBRIEF.md) |
| LDAP injection — filter metachars, auth bypass, enumeration | 4.3 Zodiac Twelve Directory Breach; F.2 Directory faction | OpenLDAP | [`phase4/zodiac-breach/DEBRIEF.md`](../phase4/zodiac-breach/DEBRIEF.md) |
| ORM injection — raw escape hatches reintroducing SQLi | 5.1 Manipulator's Firewall | MariaDB (SQLAlchemy) | [`phase5/manipulators-firewall/DEBRIEF.md`](../phase5/manipulators-firewall/DEBRIEF.md) |
| XML (tag) injection — structure tampering | 5.2 Palace Blueprint Tampering | lxml | [`phase5/blueprint-tampering/DEBRIEF.md`](../phase5/blueprint-tampering/DEBRIEF.md) |
| XXE — external entities, file read, SSRF/OOB variants | 5.3 The King's Sealed Archives; F.2 Document Import faction | lxml | [`phase5/sealed-archives/DEBRIEF.md`](../phase5/sealed-archives/DEBRIEF.md) |
| Chained, multi-technique exploitation across one target | F.1 Trick Tower Final Exam | MariaDB | [`finals/trick-tower-final/DEBRIEF.md`](../finals/trick-tower-final/DEBRIEF.md) |
| Chained exploitation across independent systems | F.2 Chairman Election Infiltration | MariaDB, MongoDB, OpenLDAP, lxml | [`finals/chairman-election/DEBRIEF.md`](../finals/chairman-election/DEBRIEF.md) |

## Coverage check

Every numbered section of the lab's source notes (injection overview
through the universal cheat sheet) has at least one row above pointing
at a built, verified challenge. No topic is covered only in prose —
every row corresponds to a real exploit a solver script runs live
against a real backend engine, with the exact payload and live output
transcribed in that challenge's own `DEBRIEF.md`.
