-- =============================================================================
-- Migracija 004 — osveževalni žetoni (najdba S-06)
-- =============================================================================
-- Doslej: en JWT z veljavnostjo 30 dni, ki ga strežnik ne more preklicati.
-- Odjava je bila samo lokalna; ponastavitev gesla ukradenega žetona ni odjavila.
--
-- Zdaj: dostopni JWT velja 1 uro. Zraven dobi aplikacija osveževalni žeton
-- (naključnih 48 bajtov), ki velja 30 dni in je shranjen tu kot SHA-256 odtis.
-- Ob vsaki uporabi se zamenja z novim (rotacija). Odjava, ponastavitev gesla
-- in brisanje računa ga prekličejo. Ukraden dostopni žeton velja največ 1 uro.
--
-- Varno za ponovni zagon.
-- =============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 odtis žetona. Sam žeton se ne hrani: če kdo prebere bazo,
    -- iz odtisa ne more sestaviti veljavnega žetona.
    token_hash  TEXT        NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    -- Kdaj je bil preklican (odjava, rotacija, ponastavitev gesla). NULL = veljaven.
    revoked_at  TIMESTAMPTZ,
    -- Ob rotaciji: kateri žeton ga je nadomestil. Če se stari žeton uporabi
    -- ŠE ENKRAT po rotaciji, je to znak kraje in prekličemo vse uporabnikove.
    replaced_by INTEGER     REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    -- Kratek opis naprave (User-Agent), samo za pregled sej. Neobvezno.
    device      TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS refresh_tokens_user_idx
    ON refresh_tokens (user_id, revoked_at);

COMMIT;
