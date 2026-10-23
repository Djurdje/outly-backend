-- 062_racun_ttwh2v4q_artikel.sql
-- PODATKOVNA MIGRACIJA (potrebuje Martinov DA in oznako odobril-martin): racun za narocilo OUT-TTWH2V4Q gre ZNOVA v izdajo. Ena vrstica, brez drugih sprememb.
--
-- Kaj se je zgodilo: po migraciji 061 (23. 10. 2026 13:02:21 UTC) je delavec poslal SalesInvoiceCreate, e-racuni pa je odgovoril
-- »HTTP 500 (apiMethod=SalesInvoiceCreate; Error nr: 1 #Item1_productCode - This field is required)«: postavka je morala imeti sifro artikla (`productCode`), ki je koda ni posiljala.
-- Koda zdaj posilja productCode (ERACUNI_ARTIKEL, privzeto VSTOPNICA; artikel je v e-racuni ustvarjen). Vrstica je spet `caka` z izidom »neznan« (poslano_at ~13:02:26 UTC).
-- Zakaj je izid znan: e-racuni je zahtevek zavrnil zaradi manjkajocega obveznega polja (vnos ni prestal preverjanja), zato po vseh dosedanjih podatkih dokumenta ni ustvaril (nepreverjeno za ta zahtevek, zato spodnji rocni pregled); pred prvim primerom (11:08) je bil
-- rocni List za 23. 10. prazen (#noDocumentsFound). PRED MERGE-OM naj Martin v e-racuni preveri, da za narocilo OUT-TTWH2V4Q (sklic) na dan 23. 10. NI nobenega dokumenta (migracija
-- brise zapis o »izidu neznan« in izda brez iskanja po referenci).
--
-- Kaj naredi: vrstico racuna (vrsta racun) tega narocila, ki je v `caka` (izid neznan, poslano_at zapisan) ali `napaka`, postavi v cisto `caka`:
--   poslano_at = NULL (delavec izda takoj, BREZ iskanja po referenci), poskusi = 0, iskanja_ne = 0, iskanje_ne_at = NULL, iskanja_nejasna = 0, zadnja_napaka = NULL,
--   naslednji_poskus_at = NOW(), prevzeto_at = NULL, prevzem_zeton = NULL. Delavec racuni.js ga nato izda natanko enkrat (en Create).
-- Kdaj NE naredi nicesar (RAISE NOTICE, migracija vseeno uspe): narocila ni (druga okolja, test), vrstica ni racun, ima stevilko / ponudnik_id / ponudnik_stevilka (dokument obstaja),
--   stanje ni `caka` ali `napaka`, ali je poslano_at mlajsi od 10 minut (zahtevek je lahko se v teku). Druge vrstice se ne dotakne.
--
-- Varnost pred dvojno izdajo: vrstica je zaklenjena (FOR UPDATE). prevzeto_at in prevzem_zeton se pocistita, zato noben zapis stare instance (deploy: dve instanci hkrati) vec ne
-- velja (vsak zapis delavca zahteva svoj prevzem_zeton); en delavec e-racuni v sistemu (racuni_najem) in prevzem vrstice (FOR NO KEY UPDATE SKIP LOCKED) zagotovita en Create.
-- Sprozilec racuni_varuj dovoli `napaka` brez stevilke -> `caka` (056); `caka` -> `caka` je dovoljeno. `naknadno` ostane TRUE (sprozilec ga ne dovoli zniziti).
--
-- Zaklep: UPDATE ene vrstice. Idempotentno: ob ponovnem zagonu vrstica ni vec caka/napaka brez stevilke -> obvestilo.

BEGIN;

DO $$
DECLARE
  v racuni%ROWTYPE;
BEGIN
  SELECT r.* INTO v FROM racuni r JOIN orders o ON o.id = r.order_id
   WHERE o.public_ref = 'OUT-TTWH2V4Q' AND r.vrsta = 'racun' FOR UPDATE OF r;
  IF NOT FOUND THEN
    RAISE NOTICE '062: racuna za narocilo OUT-TTWH2V4Q ni (druga baza ali ze obdelan): nic ni spremenjeno';
    RETURN;
  END IF;
  IF v.stevilka IS NOT NULL OR v.ponudnik_id IS NOT NULL OR v.ponudnik_stevilka IS NOT NULL THEN
    RAISE NOTICE '062: racun % (stanje %) ima stevilko ali dokument pri ponudniku: nic ni spremenjeno', v.id, v.stanje;
    RETURN;
  END IF;
  IF v.stanje NOT IN ('caka', 'napaka') THEN
    RAISE NOTICE '062: racun % je v stanju %: nic ni spremenjeno', v.id, v.stanje;
    RETURN;
  END IF;
  IF v.poslano_at IS NOT NULL AND v.poslano_at > NOW() - INTERVAL '10 minutes' THEN
    RAISE NOTICE '062: racun % ima zahtevek poslan pred manj kot 10 minutami (lahko je se v teku): nic ni spremenjeno', v.id;
    RETURN;
  END IF;
  UPDATE racuni
     SET stanje = 'caka', poslano_at = NULL, poskusi = 0, iskanja_ne = 0, iskanje_ne_at = NULL, iskanja_nejasna = 0, zadnja_napaka = NULL,
         naslednji_poskus_at = NOW(), prevzeto_at = NULL, prevzem_zeton = NULL
   WHERE id = v.id;
  RAISE NOTICE '062: racun % za narocilo OUT-TTWH2V4Q (stanje %, poslano_at %) je spet v izdaji', v.id, v.stanje, v.poslano_at;
END $$;

COMMIT;
