-- seed/mariadb/19_keys.sql: Task 2.8 "The Groundskeeper's Keys" seed data.
--
-- Mounted alongside every other seed (see docker-compose.yml, mariadb
-- service); MariaDB's entrypoint runs every *.sql file here in filename
-- order on first boot of an empty data volume.
--
-- `garden_tasks` backs an ordinary task-log lookup (challenges/phase2.py,
-- route /p2/keys), the same bare, unquoted numeric `id` sink shape as
-- every earlier floor. There is deliberately no hidden "vault" table in
-- this database at all, the flag isn't in any table here. It lives in a
-- file on the container's own filesystem instead, and is reachable only
-- because this floor's user, unlike every other challenge's user, also
-- holds the global FILE privilege.

-- Per-challenge isolation: this challenge lives in its own database with
-- its own restricted user. Its SELECT grant is scoped to this database
-- alone, exactly like every other challenge, information_schema is
-- filtered by the connecting user's privileges, so other challenges'
-- tables are invisible and cross-database SELECTs are denied outright.
-- core/db.py's mysql_conn('p2_keys') connects as this user.
CREATE DATABASE IF NOT EXISTS seiyaku_p2_keys;
CREATE USER IF NOT EXISTS 'svc_p2_keys'@'%' IDENTIFIED BY 'p2_keys_pw';
GRANT SELECT ON seiyaku_p2_keys.* TO 'svc_p2_keys'@'%';

-- The one deliberate exception in this whole lab: FILE is a *global*
-- MySQL/MariaDB privilege, it cannot be scoped to a single database the
-- way every other grant in this lab is. Granting it here is the floor's
-- entire premise, an operator who reaches for FILE (often bundled by
-- habit into a "just give the app what it needs" role, or left over from
-- an import/export task) hands out something GRANT alone cannot contain
-- to one database, no matter how carefully every other table is scoped.
-- It does not widen table access: svc_p2_keys still cannot read any other
-- challenge's database (see the Isolation note in this floor's DEBRIEF).
GRANT FILE ON *.* TO 'svc_p2_keys'@'%';

USE seiyaku_p2_keys;

CREATE TABLE IF NOT EXISTS garden_tasks (
    id   INT AUTO_INCREMENT PRIMARY KEY,
    task VARCHAR(64)  NOT NULL,
    note VARCHAR(255) NOT NULL
);

INSERT INTO garden_tasks (task, note) VALUES
    ('Prune the outer hedges',     'Done ahead of the Chairman''s last inspection.'),
    ('Re-lay the courtyard gravel', 'Ongoing, weather permitting.'),
    ('Repair the north gate hinge', 'Parts requested, awaiting delivery.');
