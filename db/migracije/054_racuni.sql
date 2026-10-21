-- 054_racuni.sql
-- DAVCNO POTRJENI RACUNI ZA LASTNE DOGODKE OUTLY (ZDavPR; Martin 21. 10. 2026): samo DODAJANJE dveh tabel, indeksov in sprozilcev, brez UPDATE/DELETE obstojecih vrstic.
--
-- Zakaj: pri dogodkih uradnega profila Outly (I50, orders.stripe_account_id = 'platform') je prodajalec NEXT DIMENSIONS. Placilo s kartico prek Stripa je po ZDavPR
-- »placilo z gotovino«, zato mora vsak tak nakup dobiti davcno potrjen racun, vsako vracilo pa dobropis (ZDavPR 6/4). Dogodki klubov (Stripe Connect) racuna od nas
-- NE dobijo (prodajalec je klub). Ta migracija postavi samo skupni del (dolg racuna, stevilcenje, dobropis, delavec); KDO dodeli EOR (ponudnik ali FURS), se ni izbrano.
--
-- racuni_zaporedje   en stevec na (poslovni prostor, elektronska naprava, poslovno leto). Stevilka racuna = A001-1-N, N od 1 vsako leto, BREZ LUKENJ (ZDavPR 5/5,
--                    interni akt 6. clen). NAMERNO NI PostgreSQL SEQUENCE: razveljavljena transakcija pri SEQUENCE pusti luknjo; vrstica stevca, zaklenjena v isti kratki
--                    transakciji kot zapis stevilke, se ob ROLLBACK vrne. Sprozilec dovoli samo +1 (ali brez spremembe) in zavrne brisanje.
--
-- racuni             ena vrstica na racun ali dobropis. Vrsto (dolg) vpise ze transakcija, v kateri narocilo postane `paid` (placila_stripe.js zakljuci) ali vracilo
--                    (uveljaviVracilo); stevilko, cas izdaje in potrditev doda delavec v ozadju (racuni.js), nikoli pot nakupa ali skena (I16).
--   vrsta            racun | dobropis. Dobropis: negativen znesek (delta vracila), ref_racun_id = izvirni racun, vir = id Stripovega vracila (re_...) ali
--                    'narocilo-<id>-vrnjeno-<skupaj>' (UNIQUE: ponovljen webhook ne naredi dvojnika). Dobropisi so v ISTEM zaporedju kot racuni (FURS vpr. 197, 198).
--   stanje           caka (dolg, brez stevilke) -> izdan (stevilka + cas izdaje zamrznjena) -> potrjen (EOR) | napaka (trajna zavrnitev, alarm).
--   prostor/naprava/leto/stevilka/izdan_at   stevilka racuna in cas izdaje; ko so zapisani, se ne spremenijo vec (sprozilec racuni_varuj).
--   zoi, eor         zascitna oznaka izdajatelja (32 hex) in enkratna identifikacijska oznaka FURS. Zapiseta se enkrat (iz NULL), nato nikoli vec.
--   message_id       UUID sporocila (ostane enak ob ponovitvi, FURS MessageID / kljuc idempotence pri ponudniku).
--   ponudnik, ponudnik_id   kdo je racun potrdil (npr. 'e-racuni') in id dokumenta pri njem. Zapiseta se enkrat.
--   naknadno         racun je bil izdan, prvi poskus potrditve pa ni uspel (FURS SubsequentSubmit / naknadno potrjevanje v 2 delovnih dneh, ZDavPR 9).
--   poskusi, naslednji_poskus_at, prevzeto_at, zadnja_napaka   vrsta dela (vzorec vracila_stripe.js).
-- Na racunu NI e-naslova ali imena kupca (poenostavljeni racun potrosniku, hramba 10 let; pravna analiza 20. 10. 2026, 4.1/12).
-- RESTRICT: racun je racunovodski dokument (kot vracila -> orders); narocila se anonimizirajo, ne brisejo.
-- Brisanje vrstic in sprememba izdanih polj: sprozilec zavrne (ZDavP-2 38/8: program ne sme omogocati spreminjanja zapisov brez hrambe izvornih podatkov).
-- TRUNCATE sprozilec NE zavrne (testne skripte praznijo `orders ... CASCADE`); v produkciji ga nobena pot ne izvaja.
--
-- Zaklep: nove tabele; REFERENCES orders vzame kratek SHARE ROW EXCLUSIVE na `orders` (kot 053). Obstojece vrstice se ne spreminjajo.

BEGIN;

CREATE TABLE IF NOT EXISTS racuni_zaporedje (
    prostor  TEXT    NOT NULL CHECK (prostor ~ '^[0-9A-Za-z]{1,20}$'),
    naprava  TEXT    NOT NULL CHECK (naprava ~ '^[0-9A-Za-z]{1,20}$'),
    leto     INTEGER NOT NULL CHECK (leto BETWEEN 2000 AND 2999),
    zadnja   BIGINT  NOT NULL DEFAULT 0 CHECK (zadnja >= 0),
    PRIMARY KEY (prostor, naprava, leto)
);

CREATE TABLE IF NOT EXISTS racuni (
    id                   BIGSERIAL   PRIMARY KEY,
    order_id             BIGINT      NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
    vrsta                TEXT        NOT NULL CHECK (vrsta IN ('racun', 'dobropis')),
    ref_racun_id         BIGINT      REFERENCES racuni(id) ON DELETE RESTRICT,
    vir                  TEXT        UNIQUE CHECK (vir IS NULL OR char_length(vir) BETWEEN 1 AND 120),
    stanje               TEXT        NOT NULL DEFAULT 'caka' CHECK (stanje IN ('caka', 'izdan', 'potrjen', 'napaka')),
    znesek_cents         INTEGER     NOT NULL,
    valuta               CHAR(3)     NOT NULL DEFAULT 'EUR',
    prostor              TEXT        CHECK (prostor IS NULL OR prostor ~ '^[0-9A-Za-z]{1,20}$'),
    naprava              TEXT        CHECK (naprava IS NULL OR naprava ~ '^[0-9A-Za-z]{1,20}$'),
    leto                 INTEGER     CHECK (leto IS NULL OR leto BETWEEN 2000 AND 2999),
    stevilka             BIGINT      CHECK (stevilka IS NULL OR stevilka >= 1),
    izdan_at             TIMESTAMPTZ,
    zoi                  TEXT        CHECK (zoi IS NULL OR zoi ~ '^[0-9a-f]{32}$'),
    eor                  UUID,
    message_id           UUID        NOT NULL DEFAULT gen_random_uuid(),
    ponudnik             TEXT        CHECK (ponudnik IS NULL OR char_length(ponudnik) BETWEEN 1 AND 40),
    ponudnik_id          TEXT        CHECK (ponudnik_id IS NULL OR char_length(ponudnik_id) BETWEEN 1 AND 200),
    potrjen_at           TIMESTAMPTZ,
    naknadno             BOOLEAN     NOT NULL DEFAULT FALSE,
    poskusi              INTEGER     NOT NULL DEFAULT 0,
    naslednji_poskus_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prevzeto_at          TIMESTAMPTZ,
    zadnja_napaka        TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- racun: pozitiven znesek, brez reference in vira; dobropis: negativen znesek, z izvirnim racunom in virom (id vracila)
    CONSTRAINT racuni_vrsta_chk CHECK (
        (vrsta = 'racun' AND ref_racun_id IS NULL AND vir IS NULL AND znesek_cents > 0)
     OR (vrsta = 'dobropis' AND ref_racun_id IS NOT NULL AND vir IS NOT NULL AND znesek_cents < 0)),
    -- stevilka, cas izdaje, prostor, naprava in leto obstajajo skupaj; brez stevilke je vrstica samo dolg (`caka`)
    CONSTRAINT racuni_stevilka_chk CHECK (
        (stevilka IS NULL) = (izdan_at IS NULL) AND (stevilka IS NULL) = (prostor IS NULL)
        AND (stevilka IS NULL) = (naprava IS NULL) AND (stevilka IS NULL) = (leto IS NULL)
        AND (stanje = 'caka') = (stevilka IS NULL)),
    CONSTRAINT racuni_potrjen_chk CHECK (stanje <> 'potrjen' OR (eor IS NOT NULL AND potrjen_at IS NOT NULL)),
    CONSTRAINT racuni_stevilka_key UNIQUE (prostor, naprava, leto, stevilka)
);

-- Natanko en racun na narocilo (dobropisov je lahko vec, vsak s svojim virom).
CREATE UNIQUE INDEX IF NOT EXISTS racuni_narocilo_racun_key ON racuni (order_id) WHERE vrsta = 'racun';
CREATE INDEX IF NOT EXISTS racuni_narocilo_idx ON racuni (order_id);
CREATE INDEX IF NOT EXISTS racuni_ref_idx ON racuni (ref_racun_id) WHERE ref_racun_id IS NOT NULL;
-- Vrsta dela delavca (racuni.js): samo nedokoncane vrstice.
CREATE INDEX IF NOT EXISTS racuni_delo_idx ON racuni (naslednji_poskus_at, id) WHERE stanje IN ('caka', 'izdan');

-- Hramba (ZDavP-2 38/8): brez brisanja; izdana polja se zapisejo enkrat in se ne spreminjajo; potrjen je koncno stanje.
CREATE OR REPLACE FUNCTION racuni_varuj() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'racuni: brisanje racuna % ni dovoljeno (ZDavP-2 38/8, hramba 10 let)', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.order_id IS DISTINCT FROM OLD.order_id OR NEW.vrsta IS DISTINCT FROM OLD.vrsta
     OR NEW.ref_racun_id IS DISTINCT FROM OLD.ref_racun_id OR NEW.vir IS DISTINCT FROM OLD.vir
     OR NEW.znesek_cents IS DISTINCT FROM OLD.znesek_cents OR NEW.valuta IS DISTINCT FROM OLD.valuta
     OR NEW.message_id IS DISTINCT FROM OLD.message_id OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'racuni: osnovnih podatkov racuna % ni dovoljeno spreminjati', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.stevilka IS NOT NULL AND (NEW.prostor IS DISTINCT FROM OLD.prostor OR NEW.naprava IS DISTINCT FROM OLD.naprava
     OR NEW.leto IS DISTINCT FROM OLD.leto OR NEW.stevilka IS DISTINCT FROM OLD.stevilka OR NEW.izdan_at IS DISTINCT FROM OLD.izdan_at) THEN
    RAISE EXCEPTION 'racuni: stevilke in casa izdaje izdanega racuna % ni dovoljeno spreminjati (ZDavP-2 38/8)', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  IF (OLD.zoi IS NOT NULL AND NEW.zoi IS DISTINCT FROM OLD.zoi) OR (OLD.eor IS NOT NULL AND NEW.eor IS DISTINCT FROM OLD.eor)
     OR (OLD.ponudnik IS NOT NULL AND NEW.ponudnik IS DISTINCT FROM OLD.ponudnik) OR (OLD.ponudnik_id IS NOT NULL AND NEW.ponudnik_id IS DISTINCT FROM OLD.ponudnik_id)
     OR (OLD.potrjen_at IS NOT NULL AND NEW.potrjen_at IS DISTINCT FROM OLD.potrjen_at) THEN
    RAISE EXCEPTION 'racuni: ZOI, EOR in podatkov ponudnika racuna % ni dovoljeno spreminjati', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  IF (OLD.stanje <> 'caka' AND NEW.stanje = 'caka') OR (OLD.stanje = 'potrjen' AND NEW.stanje <> 'potrjen') OR (OLD.naknadno AND NOT NEW.naknadno) THEN
    RAISE EXCEPTION 'racuni: nedovoljen prehod stanja racuna % (% -> %)', OLD.id, OLD.stanje, NEW.stanje USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS racuni_varuj ON racuni;
CREATE TRIGGER racuni_varuj BEFORE UPDATE OR DELETE ON racuni FOR EACH ROW EXECUTE FUNCTION racuni_varuj();

-- Stevec brez lukenj: samo +1 (ali brez spremembe), kljuci se ne spreminjajo, brez brisanja.
CREATE OR REPLACE FUNCTION racuni_zaporedje_varuj() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'racuni_zaporedje: brisanje stevca ni dovoljeno' USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.prostor IS DISTINCT FROM OLD.prostor OR NEW.naprava IS DISTINCT FROM OLD.naprava OR NEW.leto IS DISTINCT FROM OLD.leto
     OR NEW.zadnja NOT IN (OLD.zadnja, OLD.zadnja + 1) THEN
    RAISE EXCEPTION 'racuni_zaporedje: stevec % % % se sme samo povecati za 1 (% -> %)', OLD.prostor, OLD.naprava, OLD.leto, OLD.zadnja, NEW.zadnja USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS racuni_zaporedje_varuj ON racuni_zaporedje;
CREATE TRIGGER racuni_zaporedje_varuj BEFORE UPDATE OR DELETE ON racuni_zaporedje FOR EACH ROW EXECUTE FUNCTION racuni_zaporedje_varuj();

COMMENT ON TABLE racuni IS 'Davcno potrjeni racuni in dobropisi NEXT DIMENSIONS za lastne dogodke Outly (054, ZDavPR): dolg ob placilu, stevilka A001-1-N in potrditev v ozadju (racuni.js). Brez brisanja (ZDavP-2 38/8).';
COMMENT ON TABLE racuni_zaporedje IS 'Stevec zaporednih stevilk racunov po prostoru, napravi in poslovnem letu (054). Brez lukenj: vrstica, zaklenjena v transakciji izdaje, ne SEQUENCE.';

COMMIT;
