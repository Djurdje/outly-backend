-- 079_racun_a001_1_29_mail.sql
-- PODATKOVNA MIGRACIJA (Martinov DA v seji 24. 11. 2026: »potem poslji«, po pregledu predloga; oznaka odobril-martin): mail z racunom A001-1-29
-- (narocilo OUT-RV66PT2C) gre kupcu ZNOVA v posiljanje. Ena vrstica, en stolpec.
--
-- Kaj se je zgodilo: 17. 11. 2026 ob 17:21:36 UTC je posiljanje maila z racunom A001-1-29 padlo z napako Resend SDK »Unable to fetch data. The request could
-- not be resolved.« To je SPLOSEN catch okoli fetch + response.json() (node_modules/resend/dist/index.js): iz besedila NE sledi, ali je zahtevek odsel
-- (tudi prekinjena povezava po poslanem zahtevku ali neberljiv odgovor 200 da isto sporocilo). index.js (racunKupcuPosljiEno) take napake ne steje za dokazano zavrnitev, zato je
-- `mail_izid_neznan` ostal TRUE (mail se namenoma ne ponovi: dvojnik bi bil kopija brez oznake KOPIJA), od takrat vsako uro `[racun-kupcu] POZOR`.
-- Rocni pregled (24. 11. 2026, menedzer): (1) Resend API dnevnik (list-logs) za 17. 11.: 9 zahtevkov POST /emails, vsak ima svoj mail; po 17:20:04 (mail z
-- vstopnicami za OUT-RV66PT2C, dostavljen) je naslednji sele 19:17:21 (drug uporabnik) -> zahtevek za racun A001-1-29 NI prisel do Resenda. (2) Resend seznam
-- poslanih (list-emails): maila »Vas racun / Your invoice: A001-1-29« ni, vsi ostali racuni A001-1-22 .. A001-1-60 so. (3) Render dnevnik: napaka ob 17:21:36.
-- Mail torej NI bil poslan (dokaz sta Resend API dnevnik in seznam poslanih, NE besedilo napake); ponovno posiljanje je prva dostava, ne kopija.
-- POZOR za podobne primere: pred vsako taksno migracijo preveri Resend (list-logs + list-emails); samo sporocilo napake ni dovolj.
--
-- Kaj naredi: vrstici racuna (vrsta racun, A001-1-29, narocilo OUT-RV66PT2C), ki je `potrjen`, ima PDF in je mail_poslano_at NULL ter mail_izid_neznan TRUE,
-- postavi mail_izid_neznan = FALSE. Pospravljalec racunov kupcu (index.js, racunMailPogoj) jo nato prevzame in poslje mail s PDF-jem iz racuni_pdf natanko enkrat
-- (rezervacija poskusa z UPDATE ... RETURNING; mail_poskusi ostane, kot je: meja GOST_POSTA_POSKUSOV velja naprej).
-- Zamik ni potreben (pravilo +5 min iz 061/064 velja za izdajo pri ponudniku): stara in nova instanca imata isto kodo za mail, rezervacija je atomarna.
-- Kdaj NE naredi nicesar (RAISE NOTICE, migracija vseeno uspe): vrstice ni (druga baza, testi), mail je ze poslan, izid ni vec neznan, racun ni potrjen ali nima PDF,
--   ali je bil poskus rezerviran pred manj kot 1 uro (lahko je se v teku). Druge vrstice se ne dotakne. Sprozilec racuni_varuj stolpcev maila ne varuje.
-- Idempotentno: ob ponovnem zagonu mail_izid_neznan ni vec TRUE -> obvestilo.

BEGIN;

DO $$
DECLARE
  v racuni%ROWTYPE;
BEGIN
  SELECT r.* INTO v FROM racuni r JOIN orders o ON o.id = r.order_id
   WHERE o.public_ref = 'OUT-RV66PT2C' AND r.vrsta = 'racun' FOR UPDATE OF r;
  IF NOT FOUND THEN
    RAISE NOTICE '079: racuna za narocilo OUT-RV66PT2C ni (druga baza): nic ni spremenjeno';
    RETURN;
  END IF;
  IF v.prostor IS DISTINCT FROM 'A001' OR v.naprava IS DISTINCT FROM '1' OR v.stevilka IS DISTINCT FROM 29 THEN
    RAISE NOTICE '079: racun % ni A001-1-29 (% - % - %): nic ni spremenjeno', v.id, v.prostor, v.naprava, v.stevilka;
    RETURN;
  END IF;
  IF v.stanje <> 'potrjen' OR NOT v.pdf_prejet THEN
    RAISE NOTICE '079: racun % ni potrjen s PDF (stanje %, pdf %): nic ni spremenjeno', v.id, v.stanje, v.pdf_prejet;
    RETURN;
  END IF;
  IF v.mail_poslano_at IS NOT NULL OR NOT v.mail_izid_neznan THEN
    RAISE NOTICE '079: racun % (mail_poslano_at %, izid neznan %): nic ni spremenjeno', v.id, v.mail_poslano_at, v.mail_izid_neznan;
    RETURN;
  END IF;
  IF v.mail_prevzeto_at IS NOT NULL AND v.mail_prevzeto_at > NOW() - INTERVAL '1 hour' THEN
    RAISE NOTICE '079: racun % ima poskus maila rezerviran pred manj kot 1 uro (lahko je se v teku): nic ni spremenjeno', v.id;
    RETURN;
  END IF;
  UPDATE racuni SET mail_izid_neznan = FALSE WHERE id = v.id;
  RAISE NOTICE '079: racun % (A001-1-29, OUT-RV66PT2C): izid maila ni vec neznan, mail gre kupcu ob naslednjem krogu pospravljalca (poskusov do zdaj %)', v.id, v.mail_poskusi;
END $$;

COMMIT;
