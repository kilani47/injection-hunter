// seed/mongo/init_p4_loophole.js: Task 4.4 "The Loophole Clause" seed.
//
// Mounted alongside seed/mongo/init.js and the other init_p4_*.js files
// (see docker-compose.yml, `mongo` service's /docker-entrypoint-initdb.d
// mount). Fully self-contained (its own collection, `applicants`), so
// filename-sort position relative to the other init_p4_*.js files
// doesn't matter here.
//
// `applicants` backs challenges/phase4.py's p4_4 "Loophole Clause" route:
// a `$where` (server-side JavaScript) sink, a completely different bug
// *shape* from p4_1-p4_3's pure operator-dict type confusion, this one
// is a string-context break again (JS source text built by concatenation,
// same family as Phases 1-3's classic SQLi quote-breakout, just against a
// JS grammar instead of SQL). One ordinary applicant and one sealed
// applicant ("ghost") are seeded; `ghost`'s own `clearance_note` field
// carries the flag and is never surfaced by any ordinary, non-injected
// lookup this route performs on its own.

db = db.getSiblingDB("seiyaku");

db.applicants.drop();

db.applicants.insertMany([
  {
    codename: "rookie",
    clearance_note: "standard intake, nothing flagged",
  },
  {
    codename: "field.lantern",
    clearance_note: "cleared for phase 1-2 archives only",
  },
  {
    // The sealed entry. No listing or lookup this route performs on its
    // own ever names "ghost"; it only surfaces via a `$where` payload
    // that queries `this.clearance_note` directly.
    codename: "ghost",
    clearance_note: "SEIYAKU{sleep_told_the_truth}",
  },
]);

print(
  "seed/mongo/init_p4_loophole.js: applicants now has " +
    db.applicants.countDocuments({}) +
    " documents (ghost entry present: " +
    (db.applicants.countDocuments({ codename: "ghost" }) > 0) +
    ")"
);
