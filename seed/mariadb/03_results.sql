-- seed/mariadb/03_results.sql: Task 1.3 "Exam Results Board" seed data.
--
-- Mounted alongside 01_gate.sql/02_recipe.sql (see docker-compose.yml,
-- mariadb service); MariaDB's entrypoint runs every *.sql file here in
-- filename order on first boot of an empty data volume, so this runs right
-- after the Recipe Vault's seed.
--
-- `results` backs the public results-board search (challenges/phase1.py,
-- route /p1/results). It has exactly 3 columns (id, name, score), which
-- matters: the sink's query is `SELECT id,name,score FROM results WHERE
-- name LIKE '%{q}%'`, and a UNION SELECT can only splice onto that result
-- set if it supplies the same column count.
--
-- `staff` is a second, unrelated table that an ordinary results search
-- never touches: no legitimate code path in this floor ever SELECTs from
-- it. It only becomes reachable once an attacker appends their own UNION
-- SELECT onto the board's query, matching its 3-column shape. This
-- floor's flag lives in `staff.password`.

CREATE TABLE IF NOT EXISTS results (
    id    INT AUTO_INCREMENT PRIMARY KEY,
    name  VARCHAR(64) NOT NULL,
    score INT NOT NULL
);

INSERT INTO results (name, score) VALUES
    ('Gon Freecss',         92),
    ('Killua Zoldyck',      95),
    ('Kurapika',            98),
    ('Leorio Paradinight',  81),
    ('Hisoka Morow',       100);

CREATE TABLE IF NOT EXISTS staff (
    username VARCHAR(64)  NOT NULL,
    password VARCHAR(128) NOT NULL
);

INSERT INTO staff (username, password) VALUES
    ('chief_examiner', 'SEIYAKU{append_your_own_select}');
