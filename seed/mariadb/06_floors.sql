-- seed/mariadb/06_floors.sql — Task 2.1 "Automated Floor Skip" seed data.
--
-- Mounted alongside 01_gate.sql..05_medbay.sql (see docker-compose.yml,
-- mariadb service); MariaDB's entrypoint runs every *.sql file here in
-- filename order on first boot of an empty data volume, so this runs right
-- after the Medical Bay's seed.
--
-- `floors` backs the ordinary floor-viewer lookup (challenges/phase2.py,
-- route /p2/floors). A legitimate visit only ever asks "what is floor
-- <id>'s name/description?" — an unremarkable, numeric-keyed catalog, the
-- kind of table that shows up in a hundred real apps as `WHERE id={n}`
-- with the id never quoted, because "it's just a number, what could go
-- wrong."
--
-- `vault_floors` is a second, unrelated table an ordinary floor lookup
-- never touches. It holds this floor's flag in `vault_floors.secret`,
-- reachable only by walking the numeric `id` injection with sqlmap (or by
-- hand) into a UNION SELECT / subquery against `vault_floors` — never by
-- any query this app's own /p2/floors code path constructs on its own.

CREATE TABLE IF NOT EXISTS floors (
    id          INT PRIMARY KEY,
    name        VARCHAR(64) NOT NULL,
    description VARCHAR(255) NOT NULL
);

INSERT INTO floors (id, name, description) VALUES
    (1, 'Floor 200',  'The tower entrance. Rule boards line every wall.'),
    (2, 'Floor 191',  'A cavern of chains — the ceiling drops without warning.'),
    (3, 'Floor 183',  'A locked door with no visible keyhole.'),
    (4, 'Floor 176',  'A featureless corridor that never seems to end.'),
    (5, 'Floor 168',  'The exit gate. Only the rule-followers reach it.');

CREATE TABLE IF NOT EXISTS vault_floors (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    floor_name VARCHAR(64)  NOT NULL,
    secret     VARCHAR(128) NOT NULL
);

INSERT INTO vault_floors (floor_name, secret) VALUES
    ('Floor 0 (sealed)', 'SEIYAKU{sqlmap_walks_the_floors}');
