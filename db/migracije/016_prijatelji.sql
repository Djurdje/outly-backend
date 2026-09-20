-- 016_prijatelji.sql
-- Prijatelji v aplikaciji (Martin, 20. 9. 2026): "My friends" v profilu, prosnje za
-- prijateljstvo v obvestilih, "Your friends' plans" na domacem zaslonu in prenos
-- vstopnice prijatelju z izbiro iz seznama (namesto vpisa e-naslova).
--
-- friend_requests: prosnja od -> za; stanja pending -> accepted | declined | cancelled.
--   Med dvema uporabnikoma je najvec ENA cakajoca prosnja, ne glede na smer
--   (delni unikatni indeks cez LEAST/GREATEST).
-- friendships: simetricno prijateljstvo, shranjeno ENKRAT z user_a < user_b
--   (CHECK), zato ni podvojenih vrstic in vprasanje "sta prijatelja?" je ena vrstica.
-- users.share_plans_with_friends: ali prijatelji vidijo, na katere dogodke ima
--   uporabnik vstopnico ("Your friends' plans"). Privzeto TRUE (predpostavka agenta,
--   Martin ni odlocil; glej docs/STATE.md), uporabnik izklopi v Preferences.
BEGIN;

CREATE TABLE IF NOT EXISTS friend_requests (
    id            SERIAL      PRIMARY KEY,
    from_user_id  INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status        TEXT        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'accepted', 'declined', 'cancelled')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    responded_at  TIMESTAMPTZ,
    CONSTRAINT friend_requests_not_self_chk CHECK (from_user_id <> to_user_id)
);

-- Najvec ena cakajoca prosnja na par, v katerokoli smer.
CREATE UNIQUE INDEX IF NOT EXISTS friend_requests_pending_uniq
    ON friend_requests (LEAST(from_user_id, to_user_id), GREATEST(from_user_id, to_user_id))
    WHERE status = 'pending';

-- Obvestila: "moje cakajoce prosnje" (prejete).
CREATE INDEX IF NOT EXISTS friend_requests_to_pending_idx
    ON friend_requests (to_user_id) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS friendships (
    user_a      INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_b      INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_a, user_b),
    CONSTRAINT friendships_order_chk CHECK (user_a < user_b)
);

CREATE INDEX IF NOT EXISTS friendships_user_b_idx ON friendships (user_b);

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS share_plans_with_friends BOOLEAN NOT NULL DEFAULT TRUE;

COMMIT;
