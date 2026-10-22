-- 056_racuni_ponudnik_stevilka.sql
-- ENA ZAPOREDJE RACUNOV PRI PONUDNIKU, KI SAM DODELI DAVCNO STEVILKO (e-racuni.com; Martin 21. 10. 2026): samo DODAJANJE stolpcev in RAZSIRITEV pravil, brez
-- UPDATE/DELETE obstojecih vrstic (054 in 055 se ne spreminjata).
--
-- Zakaj: e-racuni.com davcno potrjenim dokumentom sam dodeli zaporedno (»fiskalno«) stevilko po blagajni (elektronski napravi) ali poslovni enoti in jo poslje FURS;
-- API je ne sprejme kot vhod (`fiscalNumber` je samo v odgovoru). Nas stevec A001-1-N (054) bi dal DRUGO stevilko za isti racun, ali pa bi imela zaporedji luknje drug
-- proti drugemu (ZDavPR 5/4-5/5). Zato pri ponudniku, ki stevilko dodeli sam, merodajna stevilka PRIDE OD PONUDNIKA, nas stevec se za ta prostor/napravo ne uporablja.
--
-- stevilka_vir        'nas' (privzeto, 054: stevilko dodeli racuni_zaporedje) | 'ponudnik' (stevilko je dodelil ponudnik, racuni_zaporedje se NE poveca).
--                     Nastavi se v ISTEM UPDATE-u, v katerem stevilka iz NULL postane N; potem je zamrznjen. V ISTEM prostoru in napravi ne smeta obstajati hkrati
--                     'nas' in 'ponudnik' (dve zaporedji bi se razhajali): sprozilec zavrne drugo vrsto.
-- ponudnik_stevilka   stevilka dokumenta pri ponudniku (npr. »2026-00005«); potrebna za sklic dobropisa na izvirni racun (salesInvoiceRef). Zapise se enkrat.
-- poslano_at          cas, ko je bil zahtevek za izdajo poslan ponudniku (zapise se PRED klicem). Ce stevilke se ni, a poslano_at je, je izid klica lahko neznan:
--                     pred novo izdajo delavec NAJPREJ poisce dokument s to referenco (orderReference = message_id), da ne nastane dvojnik.
--
-- racuni_stevilka_chk: `napaka` sme biti tudi BREZ stevilke (ponudnik je izdajo zavrnil, stevilka ni bila dodeljena); `izdan`/`potrjen` imata stevilko vedno,
-- `caka`/`preklican` je nikoli. (054: `napaka` je imela vedno stevilko, ker jo je dodelil nas stevec pred klicem ponudnika.)
-- racuni_varuj: `napaka` brez stevilke sme nazaj v `caka` (rocna ponovitev z Martinovim DA prek migracije; izdaja gre spet najprej skozi iskanje po referenci).
-- Vse ostalo (brez brisanja, zamrznjeni zapisi, ZOI/EOR enkrat, stevec samo +1, dobropis samo za izvedeno vracilo) ostane kot v 054.
--
-- Zaklep: ALTER TABLE racuni (majhna tabela, ACCESS EXCLUSIVE kratko); stolpci z konstantnim privzetkom ne prepisujejo tabele.

BEGIN;

ALTER TABLE racuni ADD COLUMN IF NOT EXISTS stevilka_vir TEXT NOT NULL DEFAULT 'nas' CHECK (stevilka_vir IN ('nas', 'ponudnik'));
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS ponudnik_stevilka TEXT CHECK (ponudnik_stevilka IS NULL OR char_length(ponudnik_stevilka) BETWEEN 1 AND 100);
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS poslano_at TIMESTAMPTZ;

ALTER TABLE racuni DROP CONSTRAINT IF EXISTS racuni_stevilka_chk;
ALTER TABLE racuni ADD CONSTRAINT racuni_stevilka_chk CHECK (
    (stevilka IS NULL) = (izdan_at IS NULL) AND (stevilka IS NULL) = (prostor IS NULL)
    AND (stevilka IS NULL) = (naprava IS NULL) AND (stevilka IS NULL) = (leto IS NULL)
    AND (stanje NOT IN ('caka', 'preklican') OR stevilka IS NULL)
    AND (stanje NOT IN ('izdan', 'potrjen') OR stevilka IS NOT NULL));

CREATE OR REPLACE FUNCTION racuni_varuj() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- Nova vrstica je vedno samo dolg (`caka`, brez stevilke, ZOI, EOR): stevilka pride IZKLJUCNO iz stevca ali od ponudnika (spodaj, prehod caka -> izdan).
  IF TG_OP = 'INSERT' THEN
    IF NEW.stanje <> 'caka' OR NEW.stevilka IS NOT NULL OR NEW.zoi IS NOT NULL OR NEW.eor IS NOT NULL OR NEW.ponudnik_id IS NOT NULL OR NEW.naknadno
       OR NEW.vracilo_uspelo IS FALSE OR NEW.stevilka_vir <> 'nas' OR NEW.ponudnik_stevilka IS NOT NULL OR NEW.poslano_at IS NOT NULL THEN
      RAISE EXCEPTION 'racuni: nov racun mora biti v stanju caka brez stevilke, ZOI in EOR' USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
  END IF;
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
  -- Vir stevilke se sme spremeniti samo v UPDATE-u, ki stevilko dodeli (NULL -> N); potem je zamrznjen.
  IF NEW.stevilka_vir IS DISTINCT FROM OLD.stevilka_vir AND NOT (OLD.stevilka IS NULL AND NEW.stevilka IS NOT NULL) THEN
    RAISE EXCEPTION 'racuni: vira stevilke racuna % ni dovoljeno spreminjati', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  -- Dodelitev stevilke (NULL -> N). Vir 'nas': N mora biti trenutna vrednost stevca istega prostora, naprave in leta (stevec se v isti transakciji poveca za 1,
  -- racuni_zaporedje_varuj). Vir 'ponudnik': stevilko je dodelil ponudnik (mora biti znan ponudnik in dokument pri njem); stevec se ne dotakne.
  -- V istem prostoru in napravi ne sme biti hkrati stevilk obeh virov (dve zaporedji se razhajata).
  IF OLD.stevilka IS NULL AND NEW.stevilka IS NOT NULL THEN
    IF NEW.stevilka_vir = 'nas' THEN
      IF NOT EXISTS (SELECT 1 FROM racuni_zaporedje z WHERE z.prostor = NEW.prostor AND z.naprava = NEW.naprava AND z.leto = NEW.leto AND z.zadnja = NEW.stevilka) THEN
        RAISE EXCEPTION 'racuni: stevilka % racuna % ni trenutna vrednost stevca (% % %)', NEW.stevilka, OLD.id, NEW.prostor, NEW.naprava, NEW.leto USING ERRCODE = 'restrict_violation';
      END IF;
    ELSIF NEW.ponudnik IS NULL OR NEW.ponudnik_id IS NULL THEN
      RAISE EXCEPTION 'racuni: stevilka racuna % je od ponudnika, zato morata biti znana ponudnik in dokument pri njem', OLD.id USING ERRCODE = 'restrict_violation';
    END IF;
    IF EXISTS (SELECT 1 FROM racuni x WHERE x.prostor = NEW.prostor AND x.naprava = NEW.naprava AND x.stevilka IS NOT NULL AND x.id <> OLD.id AND x.stevilka_vir <> NEW.stevilka_vir) THEN
      RAISE EXCEPTION 'racuni: prostor % naprava % ze ima stevilke drugega vira (dve zaporedji): racun % ne dobi stevilke', NEW.prostor, NEW.naprava, OLD.id USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  IF (OLD.zoi IS NOT NULL AND NEW.zoi IS DISTINCT FROM OLD.zoi) OR (OLD.eor IS NOT NULL AND NEW.eor IS DISTINCT FROM OLD.eor)
     OR (OLD.ponudnik IS NOT NULL AND NEW.ponudnik IS DISTINCT FROM OLD.ponudnik) OR (OLD.ponudnik_id IS NOT NULL AND NEW.ponudnik_id IS DISTINCT FROM OLD.ponudnik_id)
     OR (OLD.ponudnik_stevilka IS NOT NULL AND NEW.ponudnik_stevilka IS DISTINCT FROM OLD.ponudnik_stevilka)
     OR (OLD.potrjen_at IS NOT NULL AND NEW.potrjen_at IS DISTINCT FROM OLD.potrjen_at) THEN
    RAISE EXCEPTION 'racuni: ZOI, EOR in podatkov ponudnika racuna % ni dovoljeno spreminjati', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  -- Izid vracila (vracilo_uspelo) se sme spremeniti samo, dokler dobropis ni izdan in ni preklican; po izdaji je zamrznjen (izdan dobropis = vracilo izvedeno).
  IF NEW.vracilo_uspelo IS DISTINCT FROM OLD.vracilo_uspelo AND (OLD.stevilka IS NOT NULL OR OLD.stanje <> 'caka') THEN
    RAISE EXCEPTION 'racuni: izida vracila dobropisa % po izdaji ali preklicu ni dovoljeno spreminjati', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  -- Dobropis se izda samo za izvedeno vracilo; preklican je koncno stanje in nastane samo iz `caka` (brez stevilke).
  -- Zakaj preklican in ne DELETE: vrstica ni izdan dokument, a hrani sled (kdaj in zakaj je vracilo padlo, vir) in zapre vir (UNIQUE), da ponovljen webhook
  -- ne naredi novega dobropisa za isto zavrnjeno vracilo; brisanje bi oboje izgubilo.
  IF (OLD.stevilka IS NULL AND NEW.stevilka IS NOT NULL AND OLD.vrsta = 'dobropis' AND NEW.vracilo_uspelo IS NOT TRUE)
     OR (NEW.stanje = 'preklican' AND OLD.stanje NOT IN ('caka', 'preklican'))
     OR (OLD.stanje = 'preklican' AND NEW.stanje <> 'preklican') THEN
    RAISE EXCEPTION 'racuni: nedovoljen prehod dobropisa % (% -> %, vracilo %)', OLD.id, OLD.stanje, NEW.stanje, NEW.vracilo_uspelo USING ERRCODE = 'restrict_violation';
  END IF;
  -- Nazaj v `caka` sme samo `napaka` BREZ stevilke (ponudnik izdaje ni sprejel; rocna ponovitev). Vse ostalo ne.
  IF (OLD.stanje <> 'caka' AND NEW.stanje = 'caka' AND NOT (OLD.stanje = 'napaka' AND OLD.stevilka IS NULL))
     OR (OLD.stanje = 'potrjen' AND NEW.stanje <> 'potrjen') OR (OLD.naknadno AND NOT NEW.naknadno) THEN
    RAISE EXCEPTION 'racuni: nedovoljen prehod stanja racuna % (% -> %)', OLD.id, OLD.stanje, NEW.stanje USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON COLUMN racuni.stevilka_vir IS 'Kdo je dodelil stevilko (056): nas = racuni_zaporedje, ponudnik = ponudnik (e-racuni.com), stevec se ne dotakne. Zamrznjeno ob dodelitvi.';
COMMENT ON COLUMN racuni.ponudnik_stevilka IS 'Stevilka dokumenta pri ponudniku (056), za sklic dobropisa na izvirni racun. Zapise se enkrat.';
COMMENT ON COLUMN racuni.poslano_at IS 'Cas, ko je bil zahtevek za izdajo poslan ponudniku (056). Brez stevilke in s poslano_at je izid lahko neznan: najprej iskanje po referenci, sele nato nova izdaja.';

COMMIT;
