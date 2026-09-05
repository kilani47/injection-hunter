-- seed/mariadb/01_gate.sql — Task 1.1 "Gate of Trust" seed data.
--
-- Mounted read-only into /docker-entrypoint-initdb.d/ (see docker-compose.yml,
-- mariadb service). MariaDB's entrypoint runs every *.sql file in that
-- directory in filename order on first boot of an empty data volume, so
-- later Phase-1 tasks add 02_*.sql, 03_*.sql etc. alongside this file.
--
-- `applicants` backs the Written Exam's login gate (challenges/phase1.py,
-- route /p1/gate). The admin row's `secret` column holds this challenge's
-- flag — the vulnerable route reveals it once the attacker authenticates
-- as that row via SQL injection, without ever knowing its real password.

CREATE TABLE IF NOT EXISTS applicants (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64)  NOT NULL UNIQUE,
    password VARCHAR(128) NOT NULL,
    secret   VARCHAR(128) NOT NULL
);

INSERT INTO applicants (username, password, secret) VALUES
    ('admin', 'n3t3r0_ch41rm4n_2026', 'SEIYAKU{the_vow_was_never_sealed}'),
    ('gon',   'jajanken_rock',        'just an applicant, nothing to see here'),
    ('killua','godspeed_zzz',         'just an applicant, nothing to see here');
