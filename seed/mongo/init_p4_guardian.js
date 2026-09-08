// seed/mongo/init_p4_guardian.js — Task 4.2 "Bypassing the Archive Guardian"
// seed data.
//
// Mounted alongside seed/mongo/init.js and seed/mongo/init_p4_flag.js (see
// docker-compose.yml, `mongo` service's /docker-entrypoint-initdb.d mount).
// The official mongo image runs every *.js file in that directory, in
// filename order, once on first boot of an EMPTY /data/db volume. This
// file's name is chosen so it sorts AFTER both existing seed files:
// "init.js" < "init_p4_flag.js" < "init_p4_guardian.js" ('.' = 0x2E sorts
// before '_' = 0x5F, and "flag" < "guardian" lexicographically once both
// share the "init_p4_" prefix) — so this always runs last, appending to
// (and, for `agents`, rebuilding) whatever init.js already created instead
// of racing its own db.agents.drop() and getting silently wiped.
//
// This route (challenges/phase4.py, p4_2) logs a caller in as whichever
// document `db.agents.find_one({...})` returns first, with NO explicit
// sort — real MongoDB "natural order" behavior, not something the route
// fakes. init.js already seeded 5 `agents` documents (AG-01..AG-05)
// *before* this file ever runs, so simply appending a 6th "guardian"
// document here (via insertOne) would make it the natural *last* match,
// not first — a caller who genuinely defeats the login with a
// $ne-against-both-fields payload would land on an arbitrary ordinary
// field agent, not the privileged account, which would make the intended
// bypass payload unreliable.
//
// So this file rebuilds the whole `agents` collection instead: drop it,
// then re-insert the guardian document FIRST, followed by the same 5
// ordinary agents init.js already defined (verbatim, to preserve them for
// anything else that reaches this collection). That makes the guardian
// account genuinely first in MongoDB's natural insertion order — the
// same real behavior a $ne-on-both-fields bypass would land on in any
// unmodified collection, not a fabricated shortcut.
//
// Defense in depth on top of that (in case a MongoDB version/storage
// engine ever stops honoring natural order the way WiredTiger does today,
// or a later task adds/removes documents from this collection): the
// guardian document also carries an explicit `role: "guardian"` field,
// and challenges/phase4.py's p4_2 route checks that field directly before
// revealing the flag — it never relies on insertion order alone to decide
// *what to reveal*, only MongoDB's own real, unmodified `find_one` (no
// sort) decides *which* document a bypass query resolves to.
//
// This file running unconditionally on every fresh-volume boot (no
// idempotency guard) matches init.js's own convention — both only ever
// execute once, against an empty /data/db volume, by Mongo's own
// docker-entrypoint-initdb.d semantics.

db = db.getSiblingDB("seiyaku");

db.agents.drop();

db.agents.insertMany([
  {
    agentId: "AG-00",
    username: "guardian",
    password: "n3v3r_sh4red_do_not_guess",
    codename: "Archive Guardian",
    status: "privileged",
    role: "guardian",
    flag: "SEIYAKU{ne_null_walks_in}",
  },
  // The same 5 ordinary field agents init.js originally seeded, re-inserted
  // verbatim (content unchanged) so this rebuild doesn't lose them.
  {
    agentId: "AG-01",
    username: "field.rose",
    password: "th0rn_and_petal",
    codename: "Rose",
    status: "active",
  },
  {
    agentId: "AG-02",
    username: "field.lantern",
    password: "l1ght_the_way",
    codename: "Lantern",
    status: "active",
  },
  {
    agentId: "AG-03",
    username: "field.echo",
    password: "s0und_off",
    codename: "Echo",
    status: "inactive",
  },
  {
    agentId: "AG-04",
    username: "field.compass",
    password: "tru3_north",
    codename: "Compass",
    status: "active",
  },
  {
    agentId: "AG-05",
    username: "handler",
    password: "runs_the_desk",
    codename: "Handler",
    status: "active",
  },
]);

print(
  "seed/mongo/init_p4_guardian.js: agents rebuilt, count=" +
    db.agents.countDocuments({}) +
    " (guardian first: " +
    (db.agents.findOne({}).username === "guardian") +
    ")"
);
