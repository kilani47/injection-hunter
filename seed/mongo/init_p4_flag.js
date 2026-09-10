// seed/mongo/init_p4_flag.js: Task 4.1 "Basic Records Room" flag seed.
//
// Mounted alongside seed/mongo/init.js (see docker-compose.yml, `mongo`
// service's /docker-entrypoint-initdb.d mount). The official mongo image
// runs every *.js file in that directory, in filename order, once on
// first boot of an EMPTY /data/db volume (same convention seed/mariadb's
// *.sql files already rely on). This file's name is chosen deliberately:
// "init_p4_flag.js" sorts AFTER "init.js" ('.' = 0x2E < '_' = 0x5F in
// ASCII, and both share the "init" prefix), so it always runs *second*,
// appending to the collections init.js just (re)created, instead of
// racing init.js's own db.records.drop()/db.agents.drop() calls and
// getting silently wiped if the two ever ran in the other order.
//
// Adds exactly one more document to `records`: a sealed archive entry
// that carries the p4_1 flag under a field name ("archive_key") no
// listing or search result this app's own UI ever surfaces or
// documents. It's only reachable by a caller who gets MongoDB to honor
// a real query operator ($regex, $gt, $ne, ...) against that field
// instead of treating it as a literal string to compare against, i.e.
// exactly the blind NoSQL query-operator injection this lesson teaches
// (see challenges/phase4.py). Nothing about this document or field is
// special-cased anywhere in that route: it's queried, and returned as
// match/no-match, exactly like any other field on any other record.

db = db.getSiblingDB("seiyaku");

if (db.records.countDocuments({ recordId: "REC-0006" }) === 0) {
  db.records.insertOne({
    recordId: "REC-0006",
    username: "vault",
    password: "sealed_no_login",
    role: "sealed",
    subject: "Zodiac Twelve: Master Ledger (Sealed)",
    note:
      "This entry does not appear in any listing or search result the " +
      "front desk exposes.",
    archive_key: "SEIYAKU{operators_not_strings}",
  });
}

print(
  "seed/mongo/init_p4_flag.js: records now has " +
    db.records.countDocuments({}) +
    " documents (REC-0006 sealed entry present: " +
    (db.records.countDocuments({ recordId: "REC-0006" }) > 0) +
    ")"
);
