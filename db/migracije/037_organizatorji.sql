-- 037_organizatorji.sql
-- ORGANIZATORJI BREZ PRIZORISCA (Martin, 9. 10. 2026): promotor ali podjetje Outly prireja dogodke v tujih klubih in nima svojega lokala.
-- Odlocitev: organizator je ISTI poslovni profil kot klub (ista vrstica v `clubs`: slideshow, video, dogodki, ekipa, Stripe), samo z oznako
-- clubs.is_organizer. Nova vloga ali nova tabela se NE uvaja (vse je ze vezano na club_id; prodajalec vstopnice ostane events.club_id).
-- Vsak dogodek organizatorja nosi PRIZORISCE: klub z Outlyja (events.venue_club_id) ali prosto vpisano lokacijo (venue_name/_address/_city/_lat/_lng).
-- Gostiteljski klub dogodek vidi med svojimi dogodki (GET /events?clubId=: hosted = true), skenira pa samo organizatorjeva ekipa.
-- Podjetje Outly ima profil organizatorja z is_official = true (nastavi SAMO admin; PATCH /business/clubs/me polja ne sprejme): na Home razdelek
-- »Organized by Outly«.
--
-- Samo DODAJANJE: nov stolpec s privzeto vrednostjo (metapodatek, tabele ne prepisuje; PG11+), obstojecih podatkov ne spreminja.

BEGIN;

ALTER TABLE clubs
    ADD COLUMN IF NOT EXISTS is_organizer BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS is_official  BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE events
    ADD COLUMN IF NOT EXISTS venue_club_id INTEGER REFERENCES clubs(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS venue_name    TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS venue_address TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS venue_city    TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS venue_lat     DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS venue_lng     DOUBLE PRECISION;

-- Gostitelj ne sme biti organizator sam (dogodek v lastnem klubu nima gostitelja).
ALTER TABLE events
    DROP CONSTRAINT IF EXISTS events_venue_club_chk,
    ADD CONSTRAINT events_venue_club_chk CHECK (venue_club_id IS NULL OR venue_club_id <> club_id);

-- Koordinate prizorisca v paru in v obsegu (kot clubs_coords_chk).
ALTER TABLE events
    DROP CONSTRAINT IF EXISTS events_venue_coords_chk,
    ADD CONSTRAINT events_venue_coords_chk CHECK (
        (venue_lat IS NULL) = (venue_lng IS NULL)
        AND (venue_lat IS NULL OR (venue_lat BETWEEN -90 AND 90 AND venue_lng BETWEEN -180 AND 180))
    );

-- »Dogodki, ki jih gostim«: stran gostiteljskega kluba (GET /events?clubId=). Delni indeks: vecina dogodkov nima gostitelja.
CREATE INDEX IF NOT EXISTS events_venue_club_idx
    ON events (venue_club_id, start_at) WHERE venue_club_id IS NOT NULL;

COMMENT ON COLUMN clubs.is_organizer IS 'Organizator dogodkov brez lastnega prizorisca (037): isti profil kot klub, brez naslova in pina; vsak njegov dogodek ima prizorisce.';
COMMENT ON COLUMN clubs.is_official IS 'Uradni profil Outly (037): njegovi prihajajoci dogodki so v razdelku »Organized by Outly« na Home. Nastavi SAMO admin (admin panel).';
COMMENT ON COLUMN events.venue_club_id IS 'Gostiteljski klub z Outlyja (037). Dogodek je viden tudi na njegovi strani (hosted), skenira pa samo ekipa events.club_id. Ob izbrisu gostitelja NULL.';
COMMENT ON COLUMN events.venue_name IS 'Prosto vpisano prizorisce (037); prazno, ce je venue_club_id podan.';

COMMIT;
