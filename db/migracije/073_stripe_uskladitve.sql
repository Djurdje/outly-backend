-- 073_stripe_uskladitve.sql
-- SAMODEJNA DNEVNA USKLADITEV STRIPE <-> BAZA (Martin 27. 10. 2026: »naredi se samodejno dnevno uskladitev«; nadaljevanje outly-backend#374 tocka 2, invarianta I67).
-- Samo DODAJANJE nove tabele; obstojecih tabel in vrstic se ne dotakne (brez ALTER, brez UPDATE/DELETE, brez zaklepa na orders/tickets/spori).
--
-- stripe_uskladitve  Ena vrstica na ZAPRT dan (koledarski dan po Europe/Ljubljana). Delavec uskladitev_stripe.js enkrat na dan (prvi krog po 04:00 ljubljanskega casa)
--                    primerja Stripove naboje (charges), vracila (refunds) in spore (disputes) tega dne z bazo (orders, spori) in zapise rezultat.
--   dan                     PRIMARY KEY: ena uskladitev na dan, tudi ob vec instancah (Render ob deployu) -- zahtevek vrstice (INSERT ... ON CONFLICT DO UPDATE WHERE)
--                           je atomaren, zato drugi proces dobi 0 vrstic in dneva ne obdela.
--   stanje                  'tece' (zahtevana, v teku; zastarela > 15 min jo lahko prevzame drug proces) | 'ok' (brez razlik) | 'razlike' (>= 1 razlika, glej razlike) |
--                           'napaka' (Stripe/baza nista odgovorila ali presezena meja; neuspeh NI »ni razlik«: naslednji krog po 3 h poskusi znova).
--   stripe_* / baza_*       vsote obeh strani v CENTIH (I9): stevilo in bruto placanih naborov, vrnjeno, provizija; Stripova vracila in spori tega dne. Informativno:
--                           stanje doloca seznam razlik po narocilih, ne vsota (naboj ob polnoci se lahko zapise v sosednji dan: `mejni_stevilo`).
--   razlike                 JSONB seznam (najvec 100 vrstic), SAMO vrsta razlike + ID-ji narocil/Stripa in zneski v centih/valuta/stanje narocila. NIKOLI imena, e-naslovi,
--                           kartice, naslovi. `razlike_stevilo` je polno stevilo (seznam je lahko okrnjen).
--   napaka_koda             kratka koda (npr. api_connection_error, meja_strani); NIKOLI besedilo Stripove napake (lahko vsebuje del kljuca).
--
-- Opozorilo `stripe_razlika` (rdece) in `stripe_uskladitev_napaka` (oranzno) v admin_nadzor.js bereta to tabelo (PK po dnevu, nekaj vrstic).

BEGIN;

CREATE TABLE IF NOT EXISTS stripe_uskladitve (
    dan                     DATE        PRIMARY KEY,
    stanje                  TEXT        NOT NULL CHECK (stanje IN ('tece', 'ok', 'razlike', 'napaka')),
    poskusov                SMALLINT    NOT NULL DEFAULT 1,
    zacetek_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    izvedeno_at             TIMESTAMPTZ,
    stripe_stevilo          INTEGER,
    stripe_bruto_cents      BIGINT,
    stripe_vrnjeno_cents    BIGINT,
    stripe_provizija_cents  BIGINT,
    stripe_vracila_stevilo  INTEGER,
    stripe_vracila_cents    BIGINT,
    stripe_spori_stevilo    INTEGER,
    baza_stevilo            INTEGER,
    baza_bruto_cents        BIGINT,
    baza_vrnjeno_cents      BIGINT,
    baza_provizija_cents    BIGINT,
    baza_spori_stevilo      INTEGER,
    mejni_stevilo           INTEGER     NOT NULL DEFAULT 0,
    razlike_stevilo         INTEGER     NOT NULL DEFAULT 0,
    razlike                 JSONB       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(razlike) = 'array'),
    napaka_koda             TEXT
);

COMMENT ON TABLE stripe_uskladitve IS 'Dnevna uskladitev Stripe <-> baza (073, I67): ena vrstica na zaprt dan (Europe/Ljubljana); razlike samo ID-ji in zneski, nikoli osebni podatki.';
COMMENT ON COLUMN stripe_uskladitve.stanje IS 'tece | ok | razlike | napaka (073). napaka NI »ni razlik«: opozorilo stripe_uskladitev_napaka, ponovni poskus po 3 h.';
COMMENT ON COLUMN stripe_uskladitve.razlike IS 'JSONB seznam {vrsta, narocilo_id?, charge_id?, ...} (najvec 100), samo ID-ji in centi (073). razlike_stevilo = polno stevilo.';

COMMIT;
