-- 057_agent_zetoni.sql
-- DOSTOP ZA AGENTA (Claude) Z ZETONOM SAMO ZA BRANJE (issue #330, 1. del; Martin 23. 10. 2026, odlocitev A): samo DODAJANJE tabele in stolpca, brez UPDATE/DELETE
-- obstojecih vrstic. Nacrt: outly-hq docs/ideje/2026-10-23-admin-panel-nadgradnja.md, razdelek 3.
--
-- agent_zetoni        Zetoni agenta (`outly_agent_<32 nakljucnih bajtov base64url>`), ki jih ustvari admin v panelu. V bazi je SAMO SHA-256 zetona (zeton_sha256,
--                     64 hex znakov); cistopis je viden enkrat, ob ustvarjanju (odgovor POST /admin/api/agent-zetoni). Zeton odpre SAMO poti /agent/api/* (samo branje,
--                     brez osebnih podatkov; ARCHITECTURE I55), povsod drugje je zavrnjen (403) brez poizvedbe v bazo.
--   ime                 oznaka (kje je zeton vpisan), do 60 znakov.
--   zeton_sha256        UNIQUE: iskanje po zgoscini (zeton ima 256 bitov entropije, casovno konstantna primerjava ni potrebna).
--   obseg               seznam pravic. ZDAJ SAMO 'beri': CHECK dovoli samo to vrednost. Zmoznost ne sme obstajati pred kodo, ki jo varuje: obsega 'predlagaj' (predlogi,
--                       issue #330 2. del) in 'nujno' (3. del) razsiri sele migracija, ki prinese tudi njuna mehanizma in Martinovo oznako (DROP + ADD CONSTRAINT
--                       agent_zetoni_obseg_chk na tabeli z nekaj vrsticami). Do takrat zeton z drugim obsegom ne more nastati niti z rocnim SQL-om.
--   velja_do            rok veljavnosti (NOT NULL: zeton brez roka ne obstaja; panel privzeto 30 dni, najvec 90).
--   preklican_at        preklic v panelu; veljavnost se preveri ob VSAKEM klicu, preklic velja takoj.
--   zadnja_raba_at      najvec enkrat na minuto na zeton (pisanje ni na poti odgovora).
--   ustvaril_admin_id   users.id admina BREZ tujega kljuca (kot admin_dejanja.admin_user_id, 055): izbris admina ne sme zadeti zetona ali ga zaklepati.
--
-- admin_dejanja.agent_zeton_id   Zeton agenta, ki je dejanje sprozil (predlogi, kasnejsi deli #330). V tej migraciji ga ne pise nobena pot; stolpec je za zapis in branje
--                                (GET /agent/api/audit ga vrne). NULL = dejanje je naredil clovek (admin) sam. Brez tujega kljuca (isti razlog kot zgoraj).
--
-- Zaklep: nova tabela nima tujih kljucev, zato ne zaklepa nobene obstojece. ADD COLUMN brez privzete vrednosti je sprememba kataloga; kratek ACCESS EXCLUSIVE na
-- `admin_dejanja` (tabela, ki jo pise samo admin dejanje; `events`, `orders`, `tickets` in sken se je ne dotaknejo). migrate.js nastavi lock_timeout in migracijo ob izteku ponovi.

BEGIN;

CREATE TABLE IF NOT EXISTS agent_zetoni (
    id                 SERIAL      PRIMARY KEY,
    ime                TEXT        NOT NULL CHECK (char_length(ime) BETWEEN 1 AND 60),
    zeton_sha256       TEXT        NOT NULL UNIQUE CHECK (zeton_sha256 ~ '^[0-9a-f]{64}$'),
    obseg              TEXT[]      NOT NULL,
    velja_do           TIMESTAMPTZ NOT NULL,
    preklican_at       TIMESTAMPTZ,
    zadnja_raba_at     TIMESTAMPTZ,
    ustvaril_admin_id  INTEGER,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT agent_zetoni_obseg_chk CHECK (cardinality(obseg) >= 1 AND obseg <@ ARRAY['beri']::text[])
);

COMMENT ON TABLE agent_zetoni IS 'Zetoni agenta (057, #330): samo SHA-256 zetona, obseg (zdaj samo beri), rok, preklic. Zeton odpre samo /agent/api/* (I55). Cistopis zetona se nikjer ne hrani.';

ALTER TABLE admin_dejanja ADD COLUMN IF NOT EXISTS agent_zeton_id INTEGER;

COMMENT ON COLUMN admin_dejanja.agent_zeton_id IS 'Zeton agenta, ki je dejanje sprozil (057); NULL = dejanje je naredil admin sam. Brez tujega kljuca.';

COMMIT;
