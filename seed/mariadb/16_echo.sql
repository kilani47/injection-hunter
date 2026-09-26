-- seed/mariadb/16_echo.sql: Task 2.5 "The Echo Chamber" seed data.
--
-- Mounted alongside every other seed (see docker-compose.yml, mariadb
-- service); MariaDB's entrypoint runs every *.sql file here in filename
-- order on first boot of an empty data volume.
--
-- `echo_words` backs the chamber's word-check (challenges/phase2.py, route
-- /p2/echo). The check is a genuine boolean-blind SQL-injection sink on
-- `whisper`: a row matches ("the chamber resonates") or it doesn't ("only
-- silence"). The teaching point is that the response is deliberately noisy
-- (a random resonance reading on every request), so sqlmap's automatic
-- true/false detection can't lock on by itself, you have to define the
-- oracle for it with --string / --code and steer it with --technique.
--
-- `echo_vault` is a second, unrelated table an ordinary word-check never
-- touches. It holds this floor's flag in `echo_vault.secret`, reachable only
-- by folding a boolean subquery against it into the check's own WHERE clause
-- (exactly what sqlmap automates once you've told it what a true response
-- looks like).

-- Per-challenge isolation: this challenge lives in its own database with its
-- own restricted user, granted access to nothing else. From this challenge's
-- injection point, other challenges' tables are invisible (information_schema
-- is filtered by the connecting user's privileges) and cross-database reads
-- are denied. core/db.py's mysql_conn('p2_echo') connects as this user.
CREATE DATABASE IF NOT EXISTS seiyaku_p2_echo;
CREATE USER IF NOT EXISTS 'svc_p2_echo'@'%' IDENTIFIED BY 'p2_echo_pw';
GRANT SELECT ON seiyaku_p2_echo.* TO 'svc_p2_echo'@'%';
USE seiyaku_p2_echo;

CREATE TABLE IF NOT EXISTS echo_words (
    id   INT AUTO_INCREMENT PRIMARY KEY,
    word VARCHAR(64) NOT NULL UNIQUE
);

INSERT INTO echo_words (word) VALUES
    ('resonance'),
    ('reverberation'),
    ('overtone'),
    ('harmonic');

CREATE TABLE IF NOT EXISTS echo_vault (
    id     INT AUTO_INCREMENT PRIMARY KEY,
    label  VARCHAR(64)  NOT NULL,
    secret VARCHAR(128) NOT NULL
);

INSERT INTO echo_vault (label, secret) VALUES
    ('the true word', 'SEIYAKU{define_your_own_oracle}');
