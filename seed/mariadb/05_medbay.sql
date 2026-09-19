-- seed/mariadb/05_medbay.sql: Task 1.5 "Zevil Island Medical Bay" seed data.
--
-- Mounted alongside 01_gate.sql/02_recipe.sql/03_results.sql/04_silent.sql
-- (see docker-compose.yml, mariadb service); MariaDB's entrypoint runs every
-- *.sql file here in filename order on first boot of an empty data volume,
-- so this runs right after the Silent Room's seed.
--
-- `patients` backs the Medical Bay's status lookup (challenges/phase1.py,
-- route /p1/medbay). A legitimate check only ever asks "what is this
-- patient's status?" and the route never actually renders that value (or
-- anything else query-outcome-dependent) back to the page: every response
-- looks identical no matter what the query returns or whether it errors.
--
-- `records` is a second, unrelated table an ordinary status check never
-- touches. It holds this floor's flag in `records.secret`, reachable only
-- by folding a conditional SLEEP() against it into the status query's own
-- WHERE clause (e.g. `' OR IF(ASCII(SUBSTRING((SELECT secret FROM records
-- LIMIT 1),N,1))=88,SLEEP(2),0)-- -`) and timing how long the response
-- takes to come back, never by any query this app's own code path can
-- construct on its own, and never visible anywhere in the rendered page.

CREATE TABLE IF NOT EXISTS patients (
    id     VARCHAR(64) PRIMARY KEY,
    status VARCHAR(64) NOT NULL
);

INSERT INTO patients (id, status) VALUES
    ('zev-001', 'stable'),
    ('zev-002', 'critical'),
    ('zev-003', 'recovering'),
    ('zev-004', 'discharged');

CREATE TABLE IF NOT EXISTS records (
    id     INT AUTO_INCREMENT PRIMARY KEY,
    secret VARCHAR(128) NOT NULL
);

INSERT INTO records (id, secret) VALUES
    (1, 'SEIYAKU{time_tells_all}');
