// seed/mongo/init.js — Lesson-Group 4 "Records Room" seed data.
//
// Mounted read-only into /docker-entrypoint-initdb.d/ (see docker-compose.yml,
// mongo service). The official mongo image runs every *.js file in that
// directory once, via mongosh, on first boot of an EMPTY /data/db volume —
// so this only ever fires on a fresh `docker compose up` (or after
// `docker compose down -v`), same convention as seed/mariadb's *.sql files.
//
// Two collections back later NoSQL query-operator-injection lessons
// (Task 4.1+): `records` and `agents`, both shaped with username/password
// -style fields so an operator-injection auth bypass (e.g. supplying
// `{"$ne": null}` for a password field instead of a string) has something
// realistic to defeat. Document shape here is intentionally simple —
// later tasks own the actual challenge/route logic built on top of this.

db = db.getSiblingDB("seiyaku");

db.records.drop();
db.agents.drop();

db.records.insertMany([
  {
    recordId: "REC-0001",
    username: "clerk",
    password: "records_clerk_pw",
    role: "clerk",
    subject: "Hunter License Registry — General Index",
    note: "Public index of active Hunter licenses. Nothing sensitive here.",
  },
  {
    recordId: "REC-0002",
    username: "archivist",
    password: "dusty_shelves_99",
    role: "archivist",
    subject: "Restricted Exam Incident Reports",
    note: "Internal incident log, restricted circulation.",
  },
  {
    recordId: "REC-0003",
    username: "auditor",
    password: "ledger_check_2026",
    role: "auditor",
    subject: "Association Treasury Audit — Draft",
    note: "Draft audit notes, not yet finalized.",
  },
  {
    recordId: "REC-0004",
    username: "night_watch",
    password: "quiet_halls",
    role: "guard",
    subject: "Records Room Access Log",
    note: "Who came in and out, and when.",
  },
  {
    recordId: "REC-0005",
    username: "admin",
    password: "records_room_master",
    role: "admin",
    subject: "Zodiac Committee Correspondence — Sealed",
    note: "Administrative eyes only.",
  },
]);

db.agents.insertMany([
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

print("seed/mongo/init.js: seeded records=" + db.records.countDocuments({}) + " agents=" + db.agents.countDocuments({}));
