-- 077_izplacila.sql
-- IZPLACILA KLUBOM SELE PO DOGODKU (outly-backend#424 A; Martin 8. 11. 2026; izplacila_stripe.js, invarianta I72).
-- Connect racuni klubov dobijo rocna izplacila (Stripe settings.payouts.schedule.interval = manual); delavec `izplacila` izplaca samo denar, ki ni zadrzan
-- (dogodek se ni sproscen, odprt spor, neaktivno narocilo v vracilu). Vklop: IZPLACILA_PO_DOGODKU=1 (Martin).
-- Samo DODAJANJE novih tabel: brez ALTER, UPDATE, DELETE. BREZ tujih kljucev na clubs/events (enaka utemeljitev kot 075/076: SHARE ROW EXCLUSIVE ob deployu in
-- FOR KEY SHARE proti rezerviraj_zalogo med navalom). lock_timeout 800 ms kot 068-076 (migrate.js ob izteku ponovi).
--
-- izplacila_racuni      En Connect racun kluba (PK stripe_account_id). rocno_at = Stripe je potrdil rocni urnik (NULL = se ne / account.updated je javil drugacnega).
--                       poskusi, naslednji_at, napaka: ponovitev nastavitve urnika z narascajocim premorom (najvec 24 h).
-- izplacila             Eno izplacilo (Stripov payout na banko kluba). Vrstica v_teku je ZAHTEVEK (najvec ena na racun: delni UNIQUE indeks), nato poslano -> placano
--                       ali ni_uspelo. znesek_cents zamrznjen pred klicem Stripa (idempotentni kljuc outly-izplacilo-<id>). zadrzano/na_voljo/v_cakanju: posnetek izracuna.
--                       podrobnosti: [{event_id, cents, vrsta}] zadrzanih zneskov (samo ID-ji in centi). payout_id = Stripov po_...
-- izplacila_odobritve   Admin je izplacilo denarja dogodka odobril pred rokom (POST /admin/api/events/:id/payout-early); sled tudi v admin_dejanja (event.payout_early).
-- NIKAKRSNIH osebnih podatkov (brez e-naslovov, imen, IBAN).

BEGIN;
SET LOCAL lock_timeout = '800ms';

CREATE TABLE IF NOT EXISTS izplacila_racuni (
    stripe_account_id  TEXT        PRIMARY KEY,
    club_id            INTEGER     NOT NULL,
    livemode           BOOLEAN     NOT NULL,
    rocno_at           TIMESTAMPTZ,
    poskusi            INTEGER     NOT NULL DEFAULT 0,
    naslednji_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    napaka             TEXT,
    posodobljen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS izplacila_racuni_klub_idx ON izplacila_racuni (club_id);

CREATE TABLE IF NOT EXISTS izplacila (
    id                 BIGSERIAL   PRIMARY KEY,
    club_id            INTEGER     NOT NULL,
    stripe_account_id  TEXT        NOT NULL,
    livemode           BOOLEAN     NOT NULL,
    stanje             TEXT        NOT NULL DEFAULT 'v_teku',
    znesek_cents       INTEGER,
    valuta             CHAR(3)     NOT NULL DEFAULT 'EUR',
    zadrzano_cents     BIGINT,
    na_voljo_cents     BIGINT,
    v_cakanju_cents    BIGINT,
    podrobnosti        JSONB,
    payout_id          TEXT,
    stripe_stanje      TEXT,
    napaka             TEXT,
    ustvarjeno_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prevzeto_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    posodobljeno_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT izplacila_stanje_chk CHECK (stanje IN ('v_teku', 'poslano', 'placano', 'ni_uspelo')),
    CONSTRAINT izplacila_znesek_chk CHECK (znesek_cents IS NULL OR znesek_cents > 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS izplacila_v_teku_key ON izplacila (stripe_account_id) WHERE stanje = 'v_teku';
CREATE INDEX IF NOT EXISTS izplacila_klub_idx ON izplacila (club_id, ustvarjeno_at DESC);
CREATE INDEX IF NOT EXISTS izplacila_racun_idx ON izplacila (stripe_account_id, posodobljeno_at DESC);
CREATE INDEX IF NOT EXISTS izplacila_poslano_idx ON izplacila (posodobljeno_at) WHERE stanje = 'poslano';

CREATE TABLE IF NOT EXISTS izplacila_odobritve (
    event_id           INTEGER     PRIMARY KEY,
    admin_user_id      INTEGER,
    odobreno_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    razlog             TEXT        NOT NULL
);

COMMENT ON TABLE izplacila IS 'Izplacila Connect racunov klubov na banko po dogodku (077, #424 A, I72); brez osebnih podatkov.';
COMMENT ON TABLE izplacila_racuni IS 'Connect racuni klubov z rocnim urnikom izplacil (077, #424 A).';
COMMENT ON TABLE izplacila_odobritve IS 'Admin je izplacilo denarja dogodka odobril pred rokom (077, #424 A); sled v admin_dejanja.';

COMMIT;
