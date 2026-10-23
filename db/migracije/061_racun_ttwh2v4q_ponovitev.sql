-- 061_racun_ttwh2v4q_ponovitev.sql
-- PODATKOVNA MIGRACIJA (potrebuje Martinov DA in oznako odobril-martin): racun za narocilo OUT-TTWH2V4Q gre nazaj v izdajo. Ena vrstica, brez drugih sprememb.
--
-- Kaj se je zgodilo: prvi pravi testni nakup (23. 10. 2026). SalesInvoiceCreate je ob 11:08 UTC dal HTTP 500, ker v e-racuni nacin placila »Stripe« NI bil vklopljen
-- (Martin ga je vklopil 23. 10. ~12:50 UTC, skupaj z »racun oznaci kot placan«). Rocni SalesInvoiceList za 23. 10. je dal #noDocumentsFound: dokument pri e-racuni NI nastal.
-- Zato je izid starega klica znan (dokumenta ni), ceprav ga delavec ne more vedeti (500 = »izid neznan«, iskanje pa je ob izpadu e-racuni 12:08 padlo).
--
-- Kaj naredi: vrstico racuna (vrsta racun) tega narocila, ki je v `caka` (izid neznan, poslano_at zapisan) ali `napaka`, postavi v cisto `caka`:
--   poslano_at = NULL (delavec izda takoj, BREZ iskanja po referenci), poskusi = 0, iskanja_ne = 0, iskanje_ne_at = NULL, iskanja_nejasna = 0, zadnja_napaka = NULL,
--   naslednji_poskus_at = NOW(), prevzeto_at = NULL, prevzem_zeton = NULL. Delavec racuni.js ga nato izda natanko enkrat (en Create).
-- Kdaj NE naredi nicesar (RAISE NOTICE, migracija vseeno uspe): narocila ni (druga okolja, test), vrstica ni racun, ima stevilko / ponudnik_id / ponudnik_stevilka (dokument obstaja),
--   stanje ni `caka` ali `napaka`, ali je poslano_at mlajsi od 10 minut (zahtevek je lahko se v teku). Druge vrstice se ne dotakne.
--
-- Varnost pred dvojno izdajo: vrstica je zaklenjena (FOR UPDATE). prevzeto_at in prevzem_zeton se pocistita, zato noben zapis stare instance (deploy: dve instanci hkrati) vec ne
-- velja (vsak zapis delavca zahteva svoj prevzem_zeton); en delavec e-racuni v sistemu (racuni_najem) in prevzem vrstice (FOR NO KEY UPDATE SKIP LOCKED) zagotovita en Create.
-- Sprozilec racuni_varuj dovoli `napaka` brez stevilke -> `caka` (056); `caka` -> `caka` je dovoljeno. `naknadno` ostane TRUE (sprozilec ga ne dovoli zniziti: racun je
-- res izdan po zakonskem roku za takojsnjo izdajo, ZDavPR 9).
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
    RAISE NOTICE '061: racuna za narocilo OUT-TTWH2V4Q ni (druga baza ali ze obdelan): nic ni spremenjeno';
    RETURN;
  END IF;
  IF v.stevilka IS NOT NULL OR v.ponudnik_id IS NOT NULL OR v.ponudnik_stevilka IS NOT NULL THEN
    RAISE NOTICE '061: racun % (stanje %) ima stevilko ali dokument pri ponudniku: nic ni spremenjeno', v.id, v.stanje;
    RETURN;
  END IF;
  IF v.stanje NOT IN ('caka', 'napaka') THEN
    RAISE NOTICE '061: racun % je v stanju %: nic ni spremenjeno', v.id, v.stanje;
    RETURN;
  END IF;
  IF v.poslano_at IS NOT NULL AND v.poslano_at > NOW() - INTERVAL '10 minutes' THEN
    RAISE NOTICE '061: racun % ima zahtevek poslan pred manj kot 10 minutami (lahko je se v teku): nic ni spremenjeno', v.id;
    RETURN;
  END IF;
  UPDATE racuni
     SET stanje = 'caka', poslano_at = NULL, poskusi = 0, iskanja_ne = 0, iskanje_ne_at = NULL, iskanja_nejasna = 0, zadnja_napaka = NULL,
         naslednji_poskus_at = NOW(), prevzeto_at = NULL, prevzem_zeton = NULL
   WHERE id = v.id;
  RAISE NOTICE '061: racun % za narocilo OUT-TTWH2V4Q (stanje %, poslano_at %) je spet v izdaji', v.id, v.stanje, v.poslano_at;
END $$;

COMMIT;
