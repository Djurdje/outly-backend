-- 020_zanimanje_za_dogodek.sql
-- "I'm in" / zanimanje za dogodek (Martin, 23. 9. 2026).
--
-- Uporabnik na dogodku lahko oznaci "I'm in" (zanimanje), prijatelji to vidijo poleg
-- tistih, ki dogodek ze imajo vstopnico ("going"). "Going" se NE shranjuje nikjer -
-- izpelje se iz veljavne vstopnice (isto kot v GET /me/friends/plans, IMETNIK v index.js).
-- Shranjuje se SAMO "interested": ena vrstica na par (dogodek, uporabnik).
--
-- Nic od tega ne spreminja obstojecih podatkov: ena nova tabela.

BEGIN;

CREATE TABLE IF NOT EXISTS event_interest (
    user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_id   INTEGER     NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, event_id)
);

-- "Kdo je zainteresiran za ta dogodek" (stran dogodka, friends plans).
CREATE INDEX IF NOT EXISTS event_interest_event_idx ON event_interest (event_id);

COMMIT;
