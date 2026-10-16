// seed/mongo/init_p4_diagnostics.js: Task 4.2 "The Diagnostic Desk" seed.
//
// Mounted alongside seed/mongo/init.js and the other init_p4_*.js files
// (see docker-compose.yml, `mongo` service's /docker-entrypoint-initdb.d
// mount). The official mongo image runs every *.js file in that
// directory, in filename order, once on first boot of an EMPTY /data/db
// volume. This file is fully self-contained (its own collection,
// `incident_reports`, touched by no other seed file), so its exact
// position in that filename-sorted run order doesn't matter the way it
// does for init_p4_guardian.js's natural-order dependency on `agents`.
//
// `incident_reports` backs challenges/phase4.py's p4_2 "Diagnostic Desk"
// route: a staff-facing debugging console over the same kind of
// {field: value} MongoDB sink as p4_1/p4_3, except this route does NOT
// swallow driver exceptions, a realistic "left verbose errors on for
// easier internal debugging" antipattern. The flag lives in
// `archive_key` on one sealed report no ordinary listing ever surfaces,
// same field name/convention as p4_3's Records Room for consistency,
// reachable here via the error-based techniques this floor teaches
// (malformed-operator detection, then a one-shot $expr + $convert leak)
// rather than p4_3's boolean-blind walk.

db = db.getSiblingDB("seiyaku");

db.incident_reports.drop();

db.incident_reports.insertMany([
  {
    reportId: "INC-1001",
    subject: "Lost badge, east wing",
    status: "closed",
    severity: "low",
  },
  {
    reportId: "INC-1002",
    subject: "Unscheduled generator test",
    status: "closed",
    severity: "low",
  },
  {
    reportId: "INC-1003",
    subject: "Visitor log mismatch",
    status: "open",
    severity: "medium",
  },
  {
    // The sealed entry. Never listed, never linked, carries the flag
    // under the same `archive_key` field name every other floor in this
    // phase already uses for its own hidden value.
    reportId: "INC-9999",
    subject: "Internal audit, access review (sealed)",
    status: "sealed",
    severity: "restricted",
    archive_key: "SEIYAKU{the_error_said_it_all}",
  },
]);

print(
  "seed/mongo/init_p4_diagnostics.js: incident_reports now has " +
    db.incident_reports.countDocuments({}) +
    " documents (INC-9999 sealed entry present: " +
    (db.incident_reports.countDocuments({ reportId: "INC-9999" }) > 0) +
    ")"
);
