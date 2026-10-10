-- 041_prijave_in_bloki.sql
-- PRIJAVA ZLORABE IN BLOKIRANJE UPORABNIKOV (issue #189, Apple App Review 1.2 »uporabniska vsebina«; Martin 10. 10. 2026: »zacni delat, da bo aplikacija pripravljena«).
-- Uporabnik prijavi neprimerno vsebino ali uporabnika (POST /reports), admin prijave pregleda v admin panelu in jih razresi;
-- uporabnik drugega tiho blokira (POST /me/blocks/:userId): blok velja v OBE smeri (iskanje, prosnja za prijateljstvo, prenos vstopnice,
-- vabilo na guest listo), blokirani ne izve.
--
-- user_blocks: ena vrstica = »blocker_id je blokiral blocked_id«. Obe strani ON DELETE CASCADE: izbris racuna (DELETE /me) pobrise vse bloke,
--   ki jih je uporabnik naredil ali prejel. Odblokiranje vrstico izbrise; prijateljstvo se NE obnovi.
-- reports: prijava zlorabe. target_type + target_id je polimorfen kazalec (user | club | event | media, pri »media« je target_id id kluba) in
--   NIMA tujega kljuca: prijava ostane kot dokaz tudi, ko cilj ni vec javen ali ne obstaja (admin ga vidi kot »izbrisan«).
--   reporter_id ON DELETE SET NULL: izbris racuna prijavitelja prijavo anonimizira (ostane za moderiranje), resolved_by enako.
--   status: open -> resolved (ali nazaj); resolved_at je nastavljen natanko pri status = 'resolved' (CHECK).
--
-- Samo DODAJANJE (dve novi tabeli); obstojeci podatki in odgovori se ne spremenijo.

BEGIN;

CREATE TABLE IF NOT EXISTS user_blocks (
    blocker_id INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_id INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (blocker_id, blocked_id),
    CONSTRAINT user_blocks_not_self_chk CHECK (blocker_id <> blocked_id)
);

-- Iskanje »kdo je blokiral mene« (obratna smer) in kaskada ob izbrisu racuna blokiranega.
CREATE INDEX IF NOT EXISTS user_blocks_blocked_idx ON user_blocks (blocked_id);

CREATE TABLE IF NOT EXISTS reports (
    id          SERIAL      PRIMARY KEY,
    reporter_id INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    target_type TEXT        NOT NULL,
    target_id   INTEGER     NOT NULL,
    reason      TEXT        NOT NULL,
    details     TEXT,
    status      TEXT        NOT NULL DEFAULT 'open',
    note        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolved_by INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT reports_target_type_chk CHECK (target_type IN ('user', 'club', 'event', 'media')),
    CONSTRAINT reports_reason_chk CHECK (reason IN ('spam', 'harassment', 'inappropriate', 'impersonation', 'illegal', 'other')),
    CONSTRAINT reports_status_chk CHECK (status IN ('open', 'resolved')),
    CONSTRAINT reports_details_chk CHECK (details IS NULL OR char_length(details) <= 1000),
    CONSTRAINT reports_note_chk CHECK (note IS NULL OR char_length(note) <= 1000),
    CONSTRAINT reports_resolved_chk CHECK ((status = 'resolved') = (resolved_at IS NOT NULL))
);

-- Admin seznam po stanju (najnovejse prve).
CREATE INDEX IF NOT EXISTS reports_status_idx ON reports (status, created_at DESC);
-- Podvojena prijava istega cilja v 24 h, dnevna meja prijav na uporabnika in kaskada SET NULL ob izbrisu prijavitelja.
CREATE INDEX IF NOT EXISTS reports_reporter_idx ON reports (reporter_id, created_at DESC) WHERE reporter_id IS NOT NULL;

COMMENT ON TABLE user_blocks IS 'Bloki med uporabniki (041): blocker_id je blokiral blocked_id. Velja v obe smeri; blokirani ne izve. Izbris racuna pobrise (CASCADE).';
COMMENT ON TABLE reports IS 'Prijave zlorabe (041): uporabnik, klub, dogodek ali slika kluba (media: target_id = id kluba). Brez tujega kljuca na cilj. reporter_id SET NULL ob izbrisu racuna.';
COMMENT ON COLUMN reports.target_id IS 'Id cilja glede na target_type (users.id | clubs.id | events.id | clubs.id za media). Polimorfen, brez FK: prijava ostane kot dokaz.';

COMMIT;
