-- seed/mariadb/09_spellcard.sql: Task 3.1 "The Spell Card" seed data.
--
-- Mounted alongside 01_gate.sql..08_examiner.sql (see docker-compose.yml,
-- mariadb service); MariaDB's entrypoint runs every *.sql file here in
-- filename order on first boot of an empty data volume, so this runs right
-- after the disguised examiner's seed. Only applies on a fresh
-- `mariadb_data` volume: `docker compose down -v` before `up` if this
-- file was added after the volume already exists.
--
-- `cards` backs the ordinary spell-card lookup (challenges/phase3.py,
-- route /p3/spellcard): a small, benign catalog of Greed Island spell
-- cards, looked up by a string `id`, the kind of ordinary keyed lookup
-- that shows up constantly in real apps, `WHERE id='<value>'` with the
-- value quoted but never escaped, because "it's quoted, so it's handled."
--
-- `sealed_cards` is a second, unrelated table an ordinary card lookup never
-- touches. It holds this floor's flag in `sealed_cards.secret`, reachable
-- only by riding the `card` injection into a UNION SELECT against it,
-- never by any query this app's own /p3/spellcard code path constructs on
-- its own. Its single "true" row is styled as Greed Island's own
-- in-universe forbidden card, matching this floor's flavor text.

-- Per-challenge isolation: this challenge lives in its own database
-- with its own restricted user, granted access to nothing else. From
-- this challenge's injection point, other challenges' tables are not
-- just unreferenced but invisible (information_schema is filtered by
-- the connecting user's privileges) and cross-database reads are
-- denied. core/db.py's mysql_conn('p3_spellcard') connects as this user.
CREATE DATABASE IF NOT EXISTS seiyaku_p3_spellcard;
CREATE USER IF NOT EXISTS 'svc_p3_spellcard'@'%' IDENTIFIED BY 'p3_spellcard_pw';
GRANT SELECT ON seiyaku_p3_spellcard.* TO 'svc_p3_spellcard'@'%';
USE seiyaku_p3_spellcard;

CREATE TABLE IF NOT EXISTS cards (
    id     VARCHAR(32)  PRIMARY KEY,
    name   VARCHAR(64)  NOT NULL,
    effect VARCHAR(255) NOT NULL
);

INSERT INTO cards (id, name, effect) VALUES
    ('thunderbolt',   'Thunderbolt',
     'Deals 30 lightning damage to a single target on the field.'),
    ('guardian-ward',  'Guardian Ward',
     'Shields the caster from the next hit; expires after 2 turns.'),
    ('quicksilver',   'Quicksilver',
     'Doubles the caster''s speed until the end of the current turn.');

CREATE TABLE IF NOT EXISTS sealed_cards (
    id        INT AUTO_INCREMENT PRIMARY KEY,
    card_name VARCHAR(64)  NOT NULL,
    secret    VARCHAR(128) NOT NULL
);

INSERT INTO sealed_cards (card_name, secret) VALUES
    ('Forbidden Spell: Word of the Island', 'SEIYAKU{word_left_the_island}');
