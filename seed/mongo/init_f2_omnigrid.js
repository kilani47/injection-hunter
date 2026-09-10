// seed/mongo/init_f2_omnigrid.js — Task F.2 "Chairman Election Infiltration"
// (OmniGrid) seed data — the Mobile API faction's MongoDB system.
//
// Mounted alongside seed/mongo/init.js, init_p4_flag.js, and
// init_p4_guardian.js (see docker-compose.yml, `mongo` service's
// /docker-entrypoint-initdb.d mount). The official mongo image runs every
// *.js file in that directory, in filename order, once on first boot of an
// EMPTY /data/db volume. This filename sorts after all three existing
// Phase-4 seed files, and this file only ever touches its own
// `omnigrid_agents` collection — brand new, never shared with Phase 4's
// `agents` collection — so there is no ordering/rebuild concern like
// init_p4_guardian.js had to work around.
//
// A single service-account document is enough here: the Mobile API
// faction's route (challenges/finals.py, f2) is a login endpoint, and the
// classic $ne-on-both-fields bypass (notes §8) matches *any* document
// whose username/password fields both exist and aren't literally the
// string "1" — with only one document in the collection, that's
// unambiguous regardless of MongoDB's natural insertion order.

db = db.getSiblingDB("seiyaku");

db.omnigrid_agents.drop();

db.omnigrid_agents.insertOne({
  service: "mobile-api",
  username: "mobile-svc",
  password: "n3v3r_sh4red_mobile_pw",
  fragment: "CHAIR-M0B1LE-c91d",
});

print(
  "seed/mongo/init_f2_omnigrid.js: omnigrid_agents seeded, count=" +
    db.omnigrid_agents.countDocuments({})
);
