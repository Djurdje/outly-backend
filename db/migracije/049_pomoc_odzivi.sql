-- 049_pomoc_odzivi.sql
-- ODZIVI POD CLANKI POMOCI (13. 10. 2026, Martin: »Was this helpful?« v iOS aplikaciji). Samo DODAJANJE nove tabele; nobena obstojeca vrstica se ne spremeni.
--
-- Zakaj: clanki pomoci so staticni v aplikaciji (id npr. `buy`, `transfer`, `club-scanner`). Strezniku ni treba poznati seznama clankov (aplikacija lahko doda clanek
-- brez deploya backenda), zato `article` ni tuj kljuc, samo oblikovno omejen niz. En glas na uporabnika na clanek (PRIMARY KEY): ponovni glas prepise prejsnjega.
-- Admin vidi samo agregate (GET /admin/api/help-feedback), nikoli uporabnikov.
-- Izbris racuna: ON DELETE CASCADE, zato DELETE /me pobrise tudi glasove uporabnika (osebni podatek: vezan je na racun).
-- Zaklep: CREATE TABLE/INDEX na novi tabeli ne zaklene nobene obstojece tabele (tuj kljuc na users vzame kratek SHARE ROW EXCLUSIVE na users, kar sken ne bere vec kot za trenutek).

BEGIN;

CREATE TABLE IF NOT EXISTS help_feedback (
    user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    article    TEXT        NOT NULL,
    helpful    BOOLEAN     NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, article),
    CONSTRAINT help_feedback_article_chk CHECK (article ~ '^[a-z0-9-]{1,40}$')
);

CREATE INDEX IF NOT EXISTS help_feedback_article_idx ON help_feedback (article);

COMMENT ON TABLE help_feedback IS 'Odzivi »Was this helpful?« pod clanki pomoci (049): en glas na uporabnika na clanek, ponovni glas prepise. article = id clanka iz aplikacije (brez tujega kljuca). CASCADE ob izbrisu racuna.';

COMMIT;
