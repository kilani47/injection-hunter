-- seed/mariadb/10_cursed.sql: Task 3.2 "The Cursed Card" seed data.
--
-- Mounted alongside 01_gate.sql..09_spellcard.sql (see docker-compose.yml,
-- mariadb service); MariaDB's entrypoint runs every *.sql file here in
-- filename order on first boot of an empty data volume, so this runs right
-- after the spell card's seed. Only applies on a fresh `mariadb_data`
-- volume: `docker compose down -v` before `up` if this file was added
-- after the volume already exists.
--
-- `player_cards` backs the ordinary "inscribe a card" flow
-- (challenges/phase3.py, routes /p3/cursedcard/inscribe and
-- /p3/cursedcard/report): a small deck of card inscriptions, seeded with
-- two benign starter rows. Every row this table ever gains after boot is
-- written by a properly parameterized INSERT (see the challenge's Step 1
-- route); that write path is genuinely safe. The danger lives entirely in
-- a *separate* route that later reads a row's `inscription` back out of
-- this table and splices it, unescaped, into a brand-new query.
--
-- `vault_cards` is a second, unrelated table the safe storage route and
-- the ordinary report query never touch on their own. It holds this
-- floor's flag in `vault_cards.secret`, reachable only by getting a
-- previously-*stored* `inscription` value to ride a UNION SELECT against
-- it once the report route's own concatenation runs, never by anything a
-- single request supplies directly. Its column shape (INT, VARCHAR(64),
-- VARCHAR(128)) deliberately mirrors `player_cards` (id, owner,
-- inscription) so a 3-column UNION lines up cleanly.

CREATE TABLE IF NOT EXISTS player_cards (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    owner       VARCHAR(64)  NOT NULL,
    inscription VARCHAR(255) NOT NULL
);

INSERT INTO player_cards (owner, inscription) VALUES
    ('Biscuit',  'Handmade parchment card, smells faintly of tea leaves.'),
    ('Goreinu',  'A card traded three times before it reached this deck.');

CREATE TABLE IF NOT EXISTS vault_cards (
    id        INT AUTO_INCREMENT PRIMARY KEY,
    card_name VARCHAR(64)  NOT NULL,
    secret    VARCHAR(128) NOT NULL
);

INSERT INTO vault_cards (card_name, secret) VALUES
    ('The Cursed Card: Dormant Until Played', 'SEIYAKU{dormant_until_played}');
