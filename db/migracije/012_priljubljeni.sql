-- 012_priljubljeni.sql
-- Priljubljeni dogodki (srček) na strežniku. Do zdaj jih je aplikacija hranila
-- samo lokalno (@AppStorage), zato so se ob novi namestitvi ali drugi napravi
-- izgubili in strežnik ni vedel, kaj je komu všeč (Picked for you).
--
-- Ena vrstica = en uporabnik je označil en dogodek. Brisanje dogodka ali
-- uporabnika pobriše tudi oznake (ON DELETE CASCADE).

BEGIN;

CREATE TABLE IF NOT EXISTS event_favorites (
    user_id     INTEGER     NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    event_id    INTEGER     NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, event_id)
);

CREATE INDEX IF NOT EXISTS event_favorites_event_idx ON event_favorites (event_id);

COMMIT;
