-- 053_vracila_iz_stripa.sql
-- OBVESTILO KUPCU O VRACILU, NAREJENEM ZUNAJ OUTLYJA (issue #309): samo DODAJANJE tabele in indeksa, brez UPDATE/DELETE obstojecih vrstic.
--
-- Zakaj: vracilo, ki ga admin naredi rocno v Stripovi nadzorni plosci, pride kot webhook `charge.refunded` (placila_stripe.js vracilo()): naroceno dobi
-- refunded_cents in stanje, kupec pa ni dobil nobenega maila (maile o vracilu posilja samo obdelovalec `vracila`; Stripe sam kupcu ne poslje nicesar,
-- ker `receipt_email` ni nastavljen). Zivi test 20. 10. 2026, OUT-XEPPSF6D.
--
-- vracila_iz_stripa   ena vrstica na STRIPOVO VRACILO (re_...): kupec dobi mail »vrnili smo X« natanko enkrat na vsako vracilo, ki ni nase (Martin 20. 10. 2026:
--                     vsako novo vracilo istega naboja = nov mail). Vrstico vpise webhook charge.refunded v isti transakciji kot stanje narocila; mail gre po COMMIT-u
--                     (index.js posljiVraciloIzStripa) in ga ponavlja pospravljalec mailov.
--   vracilo_id        Stripov id vracila (re_...). Ce Stripe seznama vracil naboja ne vrne, '<charge_id>@<skupaj vrnjeno>' (eno povecanje amount_refunded).
--   znesek_cents      znesek TEGA vracila; skupaj_vrnjeno_cents = vrnjeno na naboju skupaj s tem vracilom (po casu vracil), najvec total_cents narocila.
--   valuta            valuta naboja (velike crke) ali NULL (= orders.currency).
--   mail_*            vzorec kot vracila.mail_* (natanko enkrat OB USPEHU, poskusi z narascajocim premorom, GOST_POSTA_PREMORI).
-- Mail NE gre, dokler ima naroceno vrstico v `vracila` (razen `preklicano`): tedaj kupca obvesca obdelovalec vracil (»odpovedan« / »vrnili smo«), dvojnega maila ni.
-- RESTRICT: naroceno je racunovodski dokument (kot vracila -> orders). Tabela ne hrani e-naslovov (prejemnik je orders.buyer_email ob posiljanju).

BEGIN;

CREATE TABLE IF NOT EXISTS vracila_iz_stripa (
    vracilo_id            TEXT        PRIMARY KEY,
    charge_id             TEXT        NOT NULL,
    order_id              BIGINT      NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
    znesek_cents          INTEGER     NOT NULL CHECK (znesek_cents > 0),
    skupaj_vrnjeno_cents  INTEGER     NOT NULL CHECK (skupaj_vrnjeno_cents >= znesek_cents),
    valuta                TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mail_poskusi          SMALLINT    NOT NULL DEFAULT 0,
    mail_prevzeto_at      TIMESTAMPTZ,
    mail_poslano_at       TIMESTAMPTZ
);

-- Neposlani maili (pospravljalec) in maili enega naboja (po COMMIT-u webhooka): majhna indeksa.
CREATE INDEX IF NOT EXISTS vracila_iz_stripa_mail_idx ON vracila_iz_stripa (created_at) WHERE mail_poslano_at IS NULL;
CREATE INDEX IF NOT EXISTS vracila_iz_stripa_charge_idx ON vracila_iz_stripa (charge_id);
CREATE INDEX IF NOT EXISTS vracila_iz_stripa_order_idx ON vracila_iz_stripa (order_id);

COMMENT ON TABLE vracila_iz_stripa IS 'Vracila, narejena zunaj Outlyja (Stripova nadzorna plosca), iz webhooka charge.refunded (053, #309): mail kupcu natanko enkrat na vsako Stripovo vracilo.';

COMMIT;
