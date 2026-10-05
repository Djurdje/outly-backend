-- 034_prenos_gostu.sql
-- Prenos vstopnice prijatelju BREZ racuna (Martin, 5. 10. 2026): uporabnik z racunom vpise e-naslov prijatelja, ki racuna nima;
-- prijatelj dobi mail s kodo QR (vgrajena slika), PDF in skrivno povezavo. Pravna presoja: outly-hq pravno/2026-10-05-prenos-brez-racuna.md.
--
-- Model: gostujoci IMETNIK vstopnice (ne kupec). Vstopnica ostane vstopnica narocila kupca (ta ima racun); imetnik ni vrstica v `users`:
--   * tickets.holder_is_guest        TRUE = vstopnico drzi gost (prenos na e-naslov brez racuna). Loceno od e-naslova, ker se ta ob hrambi
--                                    anonimizira (NULL), vstopnica pa NE sme zato spet postati »kupceva« (IMETNIK v index.js).
--   * tickets.holder_guest_email     normaliziran e-naslov gosta; NULL po prevzemu v racun ali anonimizaciji (konec dogodka + 30 dni).
--   * tickets.holder_guest_mail_*    stanje maila (kot orders.guest_mail_* v 033): sent_at = poslano (najvec enkrat ob uspehu), attempts/claimed_at = ponovitve.
--   * ticket_transfers.to_guest      prenos je sel na e-naslov brez racuna (to_user_id NULL do prevzema; to_email se anonimizira).
--   * ticket_transfers.age_confirmed_min  starostna meja, ki jo je POSILJATELJ potrdil (NULL = ni bila potrebna). Datuma rojstva ne hranimo.
--   * ticket_transfers.allow_guest   prenos je bil zahtevan z allow_guest (e-naslov, ne glede na to, ali je imel racun): meja zlorabe steje VSE take prenose,
--                                    sicer bi meja razkrila, ali ima naslov racun. to_email_norm = naslov brez »+oznake« (pri gmail.com/googlemail.com tudi brez pik):
--                                    meja na prejemnika se ne da obiti z »ime+1@«, »i.me@«.
--   * gost_zetoni_vstopnic           hash zetona -> vstopnica (GET /guest/ticket). token_hash je TEXT (hex sha256), NE bytea: izvoz baze je JSON.
--
-- Samo DODAJANJE (obstojecih podatkov ne spreminja). Zaklepi: ADD COLUMN s konstantno privzeto vrednostjo ali brez nje je v PG16 samo sprememba kataloga
-- (kratek ACCESS EXCLUSIVE, brez prepisa tabele); ADD CONSTRAINT ... NOT VALID vzame kratek ACCESS EXCLUSIVE, VALIDATE CONSTRAINT bere tabelo z blazjim zaklepom
-- SHARE UPDATE EXCLUSIVE (pisanje, torej tudi sken, tece naprej); CREATE INDEX (brez CONCURRENTLY) pa drzi SHARE zaklep, ki BLOKIRA pisanje v tabelo za cas gradnje
-- (delni indeksi nad skoraj praznimi vrsticami: milisekunde). migrate.js ima lock_timeout, zato migracija raje pade, kot da bi dolgo drzala zaklep.
BEGIN;

ALTER TABLE tickets ADD COLUMN IF NOT EXISTS holder_is_guest BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS holder_guest_email TEXT;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS holder_guest_mail_sent_at TIMESTAMPTZ;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS holder_guest_mail_claimed_at TIMESTAMPTZ;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS holder_guest_mail_attempts SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE tickets DROP CONSTRAINT IF EXISTS tickets_gost_imetnik_chk;
ALTER TABLE tickets ADD CONSTRAINT tickets_gost_imetnik_chk CHECK (
    (NOT holder_is_guest AND holder_guest_email IS NULL)
    OR (holder_is_guest AND holder_user_id IS NULL
        AND (holder_guest_email IS NULL OR (holder_guest_email = lower(holder_guest_email)
             AND char_length(holder_guest_email) <= 254 AND POSITION('@' IN holder_guest_email) > 1)))
) NOT VALID;
ALTER TABLE tickets VALIDATE CONSTRAINT tickets_gost_imetnik_chk;

ALTER TABLE ticket_transfers ADD COLUMN IF NOT EXISTS to_guest BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ticket_transfers ADD COLUMN IF NOT EXISTS age_confirmed_min SMALLINT;
ALTER TABLE ticket_transfers ADD COLUMN IF NOT EXISTS allow_guest BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ticket_transfers ADD COLUMN IF NOT EXISTS to_email_norm TEXT;

-- Prevzem v racun (GET /me): iskanje gostujocih vstopnic po e-naslovu.
CREATE INDEX IF NOT EXISTS tickets_gost_email_idx ON tickets (holder_guest_email) WHERE holder_guest_email IS NOT NULL;
-- Pospravljalec maila: gostujoce vstopnice, ki jim mail se ni bil poslan.
CREATE INDEX IF NOT EXISTS tickets_gost_posta_idx ON tickets (id) WHERE holder_is_guest AND holder_guest_mail_sent_at IS NULL;
-- Meje zlorabe (pisanje tujim e-naslovom): prenosi z allow_guest na posiljatelja in na (normaliziranega) prejemnika v zadnjih 24 h + globalna dnevna meja gostujocih.
CREATE INDEX IF NOT EXISTS ticket_transfers_gost_posiljatelj_idx ON ticket_transfers (from_user_id, created_at) WHERE allow_guest;
CREATE INDEX IF NOT EXISTS ticket_transfers_gost_naslov_idx ON ticket_transfers (to_email_norm, created_at) WHERE allow_guest;
CREATE INDEX IF NOT EXISTS ticket_transfers_gost_cas_idx ON ticket_transfers (created_at) WHERE to_guest;

-- token_hash je TEXT (hex sha256, 64 znakov), NE bytea (izvoz baze v JSON in db/obnovi_izvoz.js bytea ne prenesesta).
CREATE TABLE IF NOT EXISTS gost_zetoni_vstopnic (
    token_hash TEXT        PRIMARY KEY,
    ticket_id  BIGINT      NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT gost_zetoni_vstopnic_hash_chk CHECK (token_hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS gost_zetoni_vstopnic_ticket_idx ON gost_zetoni_vstopnic (ticket_id, created_at DESC);

COMMENT ON COLUMN tickets.holder_is_guest IS 'Vstopnico drzi gost (prenos na e-naslov brez racuna). Ostane TRUE tudi po anonimizaciji e-naslova; po prevzemu v racun FALSE.';
COMMENT ON COLUMN tickets.holder_guest_email IS 'E-naslov gosta imetnika. Osebni podatek; NULL po prevzemu v racun ali konec dogodka + 30 dni.';
COMMENT ON TABLE gost_zetoni_vstopnic IS 'Zetoni za pogled gostujoce vstopnice (GET /guest/ticket). Samo sha256 zetona (hex); velja do konca dogodka + 30 dni (preverja poizvedba).';

COMMIT;
