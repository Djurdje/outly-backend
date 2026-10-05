-- 033_gostujoci_nakup.sql
-- Nakup vstopnice BREZ racuna (Martin, 5. 10. 2026: kupec vpise samo e-naslov; brez kode iz maila, brez gesla, brez registracije;
-- varianto z OTP kodo je Martin izrecno zavrnil). Zaenkrat samo spletni odjemalec (/app); navadne vstopnice, VIP mize NE.
--
-- Model: gostujoce narocilo je vrstica `orders` z user_id = NULL in guest_email (NI vrstice v `users`). Razlog: orders.user_id je ze
-- nullable (po izbrisu racuna, ON DELETE SET NULL) in poti za branje ga prenesejo (LEFT JOIN users); gost se ne more zaleteti v
-- prijavo/povezavo po e-naslovu, ne pojavi se v iskanju uporabnikov, prijateljih ali adminovem seznamu in ne zaseda uporabniskega imena.
-- Pogled gosta je ZETON (nakljucnih 32 B, v bazi samo sha256), ne e-naslov. Prevzem v racun: ko se prijavi uporabnik s potrjenim istim
-- e-naslovom, GET /me nastavi orders.user_id (guest_email ostane za idempotenco in posto).
--
--   * orders.guest_email           normaliziran (lower, <= 254) e-naslov gosta; NULL = navadno narocilo. Ostane po prevzemu v racun.
--   * orders.guest_terms_*         pogoji, ki jih je gost sprejel (verzija + cas), kot ob registraciji.
--   * orders.guest_age_min         starostna meja, za katero je gostova izjava o starosti prestala preverbo (NULL = datum ni bil podan).
--                                  Datuma rojstva NE shranjujemo (GDPR 5(1)(c)).
--   * orders.guest_mail_*          stanje maila z vstopnico: sent_at = poslano (najvec enkrat), attempts/claimed_at = ponovni poskusi.
--   * gost_zetoni                  hash zetona -> narocilo. Vec zetonov na narocilo (odgovor nakupa, success_url Stripa, mail, ponovitev):
--                                  ker v bazi ni cistopisa zetona, ga mail iz webhooka ne bi mogel ponoviti, zato se kuje svez zeton.
--   * orders_gost_cakajoce_key     najvec 1 cakajoce (neplacano) gostujoce narocilo na e-naslov in dogodek (zaloga je zaklenjena ~35 min).
--   * orders_gost_idempotency_key  Idempotency-Key je vezan na gostov e-naslov (kot (user_id, kljuc) pri racunih, I18).
--
-- Samo DODAJANJE: stolpci brez privzete vrednosti (razen stevca poskusov), omejitve NOT VALID + VALIDATE (brez dolgega zaklepa),
-- ena nova tabela in trije indeksi. Obstojecih podatkov ne bere in ne spreminja.
BEGIN;

ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_email TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_terms_version TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_terms_accepted_at TIMESTAMPTZ;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_age_min SMALLINT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_mail_sent_at TIMESTAMPTZ;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_mail_claimed_at TIMESTAMPTZ;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_mail_attempts SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE orders DROP CONSTRAINT IF EXISTS orders_guest_chk;
ALTER TABLE orders ADD CONSTRAINT orders_guest_chk CHECK (
    guest_email IS NULL OR (
        guest_email = lower(guest_email)
        AND char_length(guest_email) <= 254
        AND POSITION('@' IN guest_email) > 1
        AND table_id IS NULL                      -- VIP mize samo za racune (alkohol 18+, prenos prijateljem)
        AND guest_terms_version IS NOT NULL
        AND guest_terms_accepted_at IS NOT NULL
    )
) NOT VALID;
ALTER TABLE orders VALIDATE CONSTRAINT orders_guest_chk;

-- Gost: Idempotency-Key je vezan na e-naslov. Delni unikaten indeks (kot orders_idempotency_key za uporabnike).
CREATE UNIQUE INDEX IF NOT EXISTS orders_gost_idempotency_key ON orders (guest_email, idempotency_key)
    WHERE guest_email IS NOT NULL AND idempotency_key IS NOT NULL;

-- Zloraba: neplacano gostujoce narocilo drzi zalogo; najvec 1 na (e-naslov, dogodek). Odlocitev je v bazi (I20).
CREATE UNIQUE INDEX IF NOT EXISTS orders_gost_cakajoce_key ON orders (guest_email, event_id)
    WHERE guest_email IS NOT NULL AND status = 'pending';

-- Prevzem v racun (GET /me): iskanje gostujocih narocil po e-naslovu, samo se neprevzeta.
CREATE INDEX IF NOT EXISTS orders_gost_prevzem_idx ON orders (guest_email)
    WHERE guest_email IS NOT NULL AND user_id IS NULL;

-- Pospravljalec maila: placana gostujoca narocila, ki jim mail se ni bil poslan.
CREATE INDEX IF NOT EXISTS orders_gost_posta_idx ON orders (id)
    WHERE guest_email IS NOT NULL AND guest_mail_sent_at IS NULL AND status = 'paid';

CREATE TABLE IF NOT EXISTS gost_zetoni (
    token_hash BYTEA       PRIMARY KEY,
    order_id   BIGINT      NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT gost_zetoni_hash_chk CHECK (octet_length(token_hash) = 32)
);
CREATE INDEX IF NOT EXISTS gost_zetoni_order_idx ON gost_zetoni (order_id, created_at DESC);

COMMENT ON COLUMN orders.guest_email IS 'E-naslov gosta, ki je kupil brez racuna (user_id NULL do prevzema). Osebni podatek kot buyer_email; ob izbrisu racuna se postavi na NULL.';
COMMENT ON TABLE gost_zetoni IS 'Zetoni za pogled gostujocega narocila (GET /guest/order). Samo sha256 zetona (32 B); velja do konca dogodka + 30 dni (preverja poizvedba, ne stolpec).';

COMMIT;
