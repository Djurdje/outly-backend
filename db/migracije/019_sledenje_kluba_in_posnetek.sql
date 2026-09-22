-- 019_sledenje_kluba_in_posnetek.sql
-- Sledenje klubu in posnetek koncanega dogodka (Martin, 22. 9. 2026).
--
-- 1) club_follows: "Follow" na strani kluba. Ena vrstica na par (klub, uporabnik) —
--    stevilo sledilcev je COUNT te tabele, ne stolpec, ki bi se lahko razsel z resnico.
--    Lajkanje kluba ne obstaja in ne bo: srcek ostane samo na dogodkih (event_favorites, 012).
-- 2) club_event_notifications: ko klub objavi dogodek, vsak sledilec dobi vrstico.
--    seen_at NULL = neprebrano -> zvonec na domacem zaslonu (isti vzorec kot 017).
--    UNIQUE (user_id, event_id): ponovna objava istega dogodka ne podvoji obvestila.
-- 3) events.recap_video_url: video "kako je bilo" na KONCANEM dogodku. Na strani kluba
--    zamenja plakat. Backend dovoli video samo na TOP 3 koncanih dogodkih kluba po
--    prodanih vstopnicah (glej index.js, preveriPosnetek) — brez te meje bi stran kluba
--    nalagala poljubno mnogo videov.
--
-- Nic od tega ne spreminja obstojecih podatkov: dve novi tabeli in en stolpec s privzetkom ''.
BEGIN;

CREATE TABLE IF NOT EXISTS club_follows (
    club_id    INTEGER     NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (club_id, user_id)
);

-- "Katerim klubom sledim" (seznam v aplikaciji).
CREATE INDEX IF NOT EXISTS club_follows_user_idx ON club_follows (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS club_event_notifications (
    id         SERIAL      PRIMARY KEY,
    user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_id   INTEGER     NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    seen_at    TIMESTAMPTZ,
    CONSTRAINT club_event_notifications_uniq UNIQUE (user_id, event_id)
);

-- Obvestila: "moja neprebrana obvestila o dogodkih".
CREATE INDEX IF NOT EXISTS club_event_notifications_unseen_idx
    ON club_event_notifications (user_id) WHERE seen_at IS NULL;

ALTER TABLE events
    ADD COLUMN IF NOT EXISTS recap_video_url TEXT NOT NULL DEFAULT '';

COMMIT;
