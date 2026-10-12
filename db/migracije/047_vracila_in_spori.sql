-- 047_vracila_in_spori.sql
-- VRACILA IN SPORI (issue #190, prva faza): vrsta vracil, zapis odpovedi dogodka, spori (chargeback). Samo DODAJANJE.
--
-- Zakaj: odpoved dogodka je do zdaj samo nastavila events.status = 'cancelled'; denarja ni vrnil nihce (vracilo se je delalo rocno v Stripovi
-- nadzorni plosci in bi ga brez reverse_transfer placala platforma). Martinova odlocitev 12. 10. 2026 (DECISIONS): kupec dobi CELOTEN znesek,
-- glavnico vrne klub (reverse_transfer), Outly vrne provizijo, Stripovo pristojbino nosi klub.
--
-- vracila               vrsta vracil. Vrstica = en poskus, da se naroceno vrne kupcu. Masovno vracilo NE tece v zahtevku: odpoved dogodka samo vstavi vrstice
--                       (en INSERT ... SELECT), obdelovalec v ozadju (vracila_stripe.js) jih po eno prevzema (FOR UPDATE SKIP LOCKED), z omejitvijo hitrosti,
--                       ponovitvami in Stripovim idempotentnim kljucem. UNIQUE (order_id, razlog) = naroceno se zaradi istega razloga vrne najvec enkrat.
--   razlog              'event_cancelled' (dogodek odpovedan) | 'inactive_order' (placilo za ze preklicano/neuspelo naroceno: nasa napaka, kupec dobi vse)
--   stanje              'caka' | 'v_teku' (prevzeto) | 'opravljeno' | 'ni_uspelo' (alarm, ponovi admin) | 'rocno' (zahteva cloveka: drug nacin Stripa, brez kljuca,
--                       nepricakovano stanje) | 'preklicano' (dogodek ni vec odpovedan, preden je steklo vracilo)
-- odpovedi_dogodkov     kdaj je dogodek PREJ ODPOVEDAN (sprozilec na events). Obdelovalec samodejno vraca samo za dogodke, ki so v tej tabeli:
--                       dogodki, odpovedani pred to migracijo, NISO v njej (migracija ne dela UPDATE), zato jih nov obdelovalec ne dotakne, dokler lastnik
--                       izrecno ne pokliche DELETE /events/:id.
-- spori                 Stripov spor (dp_...) iz webhooka charge.dispute.*. SAMO zapis stanja in obvestilo lastniku kluba; denarja ne premika, vstopnice ne razveljavi
--                       (izid izgubljenega spora ni odlocen).
--
-- Brez UPDATE/DELETE obstojecih vrstic. Novi tabeli ne spreminjata nobenega obstojecega stolpca ali poizvedbe.

BEGIN;

CREATE TABLE IF NOT EXISTS vracila (
    id                          BIGSERIAL   PRIMARY KEY,
    -- RESTRICT: naroceno je racunovodski dokument (kot orders -> events); vrstica vracila ga spremlja.
    order_id                    BIGINT      NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
    event_id                    INTEGER     NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
    razlog                      TEXT        NOT NULL,
    stanje                      TEXT        NOT NULL DEFAULT 'caka',
    -- Znesek v centih EUR (I9). event_cancelled: NULL do prvega poskusa (takrat total - refunded_cents iz baze, nato zamrznjen zaradi idempotentnega kljuca);
    -- inactive_order: znesek seje, ki jo je kupec placal.
    znesek_cents                INTEGER,
    -- inactive_order: narocilo nima stripe_payment_intent_id (ni bilo placano), zato ga nosi vrstica; session/livemode za preverbo nacina (I36).
    payment_intent_id           TEXT,
    checkout_session_id         TEXT,
    stripe_livemode             BOOLEAN,
    -- Stripe: vracilo (re_...) in vracilo provizije (fr_...). Nastavljena, ko Stripe vracilo sprejme; ponovni poskus teh korakov ne ponovi.
    stripe_vracilo_id           TEXT,
    application_fee_id          TEXT,
    provizija_za_vrnitev_cents  INTEGER,
    provizija_vracilo_id        TEXT,
    stripe_pristojbina_cents    INTEGER,
    brez_stripa                 BOOLEAN     NOT NULL DEFAULT FALSE,
    poskusi                     SMALLINT    NOT NULL DEFAULT 0,
    naslednji_poskus_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prevzeto_at                 TIMESTAMPTZ,
    napaka                      TEXT,
    -- Obvestilo kupcu (razlog event_cancelled): vzorec kot gostov mail (natanko enkrat OB USPEHU, poskusi z narascajocim premorom).
    mail_poskusi                SMALLINT    NOT NULL DEFAULT 0,
    mail_prevzeto_at            TIMESTAMPTZ,
    mail_poslano_at             TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    opravljeno_at               TIMESTAMPTZ,
    CONSTRAINT vracila_razlog_chk  CHECK (razlog IN ('event_cancelled','inactive_order')),
    CONSTRAINT vracila_stanje_chk  CHECK (stanje IN ('caka','v_teku','opravljeno','ni_uspelo','rocno','preklicano')),
    CONSTRAINT vracila_znesek_chk  CHECK (znesek_cents IS NULL OR znesek_cents >= 0),
    CONSTRAINT vracila_provizija_chk CHECK (provizija_za_vrnitev_cents IS NULL OR provizija_za_vrnitev_cents >= 0)
);

-- Naroceno se zaradi istega razloga vrne najvec enkrat (ponovni DELETE dogodka, sweep in ponovni zagon obdelovalca ne podvojijo).
CREATE UNIQUE INDEX IF NOT EXISTS vracila_narocilo_razlog_key ON vracila (order_id, razlog);
-- Cakajoca vracila (obdelovalec) in vracila, ki zahtevajo pozornost (admin).
CREATE INDEX IF NOT EXISTS vracila_caka_idx ON vracila (naslednji_poskus_at) WHERE stanje = 'caka';
CREATE INDEX IF NOT EXISTS vracila_pozornost_idx ON vracila (stanje, id) WHERE stanje IN ('v_teku','ni_uspelo','rocno');
CREATE INDEX IF NOT EXISTS vracila_dogodek_idx ON vracila (event_id);
-- Neposlana obvestila kupcem.
CREATE INDEX IF NOT EXISTS vracila_mail_idx ON vracila (id) WHERE stanje = 'opravljeno' AND razlog = 'event_cancelled' AND mail_poslano_at IS NULL;

COMMENT ON TABLE vracila IS 'Vrsta vracil (047, #190): odpoved dogodka in placilo za neaktivno naroceno. Obdelovalec vracila_stripe.js; Stripe reverse_transfer, idempotentni kljuc outly-vracilo-<id> (I37).';

CREATE TABLE IF NOT EXISTS odpovedi_dogodkov (
    event_id      INTEGER     PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    odpovedan_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE odpovedi_dogodkov IS 'Kdaj je bil dogodek odpovedan (sprozilec na events, 047). Samo dogodki iz te tabele sprozijo samodejna vracila; starejsi odpovedani dogodki ne.';

CREATE OR REPLACE FUNCTION zabelezi_odpoved_dogodka() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.status IS NOT DISTINCT FROM 'cancelled' THEN RETURN NEW; END IF;   -- ze odpovedan: cas prve odpovedi ostane
    END IF;
    INSERT INTO odpovedi_dogodkov (event_id, odpovedan_at) VALUES (NEW.id, NOW())
    ON CONFLICT (event_id) DO UPDATE SET odpovedan_at = EXCLUDED.odpovedan_at;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS events_odpoved ON events;
CREATE TRIGGER events_odpoved AFTER INSERT OR UPDATE OF status ON events
    FOR EACH ROW WHEN (NEW.status = 'cancelled') EXECUTE FUNCTION zabelezi_odpoved_dogodka();

CREATE TABLE IF NOT EXISTS spori (
    id                      TEXT        PRIMARY KEY,                 -- Stripov dp_...
    -- NULL: spora ne moremo povezati z naroceno (alarm). RESTRICT kot drugje.
    order_id                BIGINT      REFERENCES orders(id) ON DELETE RESTRICT,
    payment_intent_id       TEXT,
    charge_id               TEXT,
    stanje                  TEXT        NOT NULL,                    -- Stripov status: needs_response, under_review, won, lost, warning_*, ...
    razlog                  TEXT,                                    -- Stripov reason: fraudulent, product_not_received, ...
    znesek_cents            INTEGER     NOT NULL DEFAULT 0,
    valuta                  CHAR(3),
    rok_dokazov_at          TIMESTAMPTZ,
    ustvarjen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    zaprt_at                TIMESTAMPTZ,
    posodobljen_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Obvestilo lastniku kluba: ob odprtju in ob zaprtju (loceni stevci poskusov, natanko enkrat ob uspehu).
    mail_odprt_poskusi      SMALLINT    NOT NULL DEFAULT 0,
    mail_odprt_prevzeto_at  TIMESTAMPTZ,
    mail_odprt_poslano_at   TIMESTAMPTZ,
    mail_zaprt_poskusi      SMALLINT    NOT NULL DEFAULT 0,
    mail_zaprt_prevzeto_at  TIMESTAMPTZ,
    mail_zaprt_poslano_at   TIMESTAMPTZ,
    CONSTRAINT spori_znesek_chk CHECK (znesek_cents >= 0)
);
CREATE INDEX IF NOT EXISTS spori_narocilo_idx ON spori (order_id);
CREATE INDEX IF NOT EXISTS spori_mail_idx ON spori (ustvarjen_at) WHERE mail_odprt_poslano_at IS NULL OR (zaprt_at IS NOT NULL AND mail_zaprt_poslano_at IS NULL);
COMMENT ON TABLE spori IS 'Stripovi spori (chargeback) iz webhooka charge.dispute.* (047, #190): samo stanje in obvestilo; denarja ne premika, vstopnice ne razveljavi.';

COMMIT;
