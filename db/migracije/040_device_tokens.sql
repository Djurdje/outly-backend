-- 040_device_tokens.sql
-- POTISNA OBVESTILA (APNs): ZETONI NAPRAV (issue #183, Martin 9. 10. 2026: kljuc in Render secrets nastavljeni).
-- Aplikacija (iOS, #184) po dovoljenju za obvestila prijavi zeton naprave (POST /me/devices); backend ob dogodkih, ki danes polnijo zvonec
-- (prejeta vstopnica, objava dogodka kluba, vabilo na guest listo, strezba VIP mize), poleg vrstice v zvoncu poslje se push.
--
-- device_tokens: en zeton = ena vrstica (UNIQUE). Isti zeton na drugem racunu (odjava in prijava na isti napravi) prepise user_id.
--   user_id    ON DELETE CASCADE: izbris racuna (DELETE /me) pobrise tudi naprave.
--   invalid_at nastavi backend, ko APNs odgovori 410 (Unregistered) ali 400 BadDeviceToken; takemu zetonu se ne poslje vec,
--              dokler ga aplikacija znova ne registrira (POST /me/devices postavi invalid_at na NULL).
--   last_seen_at = zadnja registracija (POST /me/devices).
-- Zeton je dolg 64-200 znakov (APNs: 64 hex znakov, Apple pusca prostor za daljse); format preveri koda, dolzino tudi baza.
--
-- Samo DODAJANJE (nova tabela); obstojeci podatki in odgovori se ne spremenijo.

BEGIN;

CREATE TABLE IF NOT EXISTS device_tokens (
    id           SERIAL      PRIMARY KEY,
    user_id      INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token        TEXT        NOT NULL UNIQUE,
    platform     TEXT        NOT NULL DEFAULT 'ios',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    invalid_at   TIMESTAMPTZ,
    CONSTRAINT device_tokens_platform_chk CHECK (platform IN ('ios')),
    CONSTRAINT device_tokens_token_dolzina_chk CHECK (char_length(token) BETWEEN 64 AND 200)
);

-- Iskanje zetonov prejemnikov (push) in pospravljanje ob izbrisu racuna.
CREATE INDEX IF NOT EXISTS device_tokens_user_idx ON device_tokens (user_id);

COMMENT ON TABLE device_tokens IS 'Zetoni naprav za potisna obvestila APNs (040). Zeton je skrivnost naprave: nikoli v dnevniku, nikoli v odgovorih API-ja.';
COMMENT ON COLUMN device_tokens.invalid_at IS 'Nastavi backend ob odzivu APNs 410 / Unregistered ali 400 BadDeviceToken (DeviceTokenNotForTopic je napaka nastavitve topica in zetona NE oznaci). POST /me/devices ga postavi na NULL.';

COMMIT;
