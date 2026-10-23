-- 066_brisanje_demo_klubov.sql
-- PODATKOVNA MIGRACIJA, KI BRISE PRODUKCIJSKE PODATKE (potrebuje Martinov izrecni DA in oznako odobril-martin; agent je ne sme mergati sam).
--
-- Martin, 23. 10. 2026 (seja https://claude.ai/code/session_01LMxp2PJkvbbQzBQDG5fCkW), dobesedno:
--   »Prvo hocem da vse klube ki so bili prej izbrises razen nas OUTLY nesmes izbrisati iz aplikacije! in zbrisi se evente ki so bili na njih vse
--    ker je bilo samo demo in imamo zdaj taprave evente npr Outly quickie ki je pravi in ga ne smes izbrisati.«
--
-- KAJ BRISE: vse klube z `clubs.is_demo = TRUE` (v produkciji Nexus, Mirage, Mansion, Olie, Velvet; oznako jim je dala 050), vse njihove dogodke
-- (`events.club_id` = demo klub) in vse, kar visi na njih: narocila (testna), vstopnice, prenosi vstopnic, guest liste in njihovi clani, gost zetoni, mize,
-- paketi, rezervacije miz, strezba, vracila testnih narocil, ogledi, sledilci, obvestila o dogodkih, priljubljeni in zanimanje, ekipa kluba (clani, vabila),
-- promo kode demo klubov, odpovedi dogodkov, prijave (reports), ki kazejo na izbrisani klub ali dogodek. Odprti predlogi agenta za izbrisane dogodke/klube
-- dobijo stanje `potekel` (sicer bi v panelu cakali na klik, ki bi padel). Brise v pravem vrstnem redu (veliko tujih kljucev je ON DELETE RESTRICT).
--
-- KAJ NE BRISE: nobenega uporabnika (tudi lazni lastniki demo klubov ostanejo; GET /me jim vrne club_id null in clubs [], poslovne poti dajo 404 »Club not found«),
-- nobenega kluba z is_demo = FALSE (Outly in vsak drug klub), nobenega dogodka teh klubov (QUICKIE, Outly Launch Party), njihovih narocil, vstopnic ...,
-- admin_dejanja (dnevnik dejanj) in predlogi_dejanj (zgodovina). Funkcija `is_demo` (stolpec, stikalo v panelu, 409 demo_club) ostane: brisemo samo podatke.
--
-- VAROVALA (RAISE EXCEPTION: migracija pade, transakcija se razveljavi, NIC se ne izbrise, deploy pade in Render obdrzi staro razlicico):
--   (a) kateri koli izbrisan dogodek ima PRAVO (ne testno) narocilo, ki ni failed/cancelled (paid, partially_refunded, refunded, pending): to je denar ali
--       obveznost do kupca. Testno = enaka definicija kot SQL_TESTNO_NAROCILO v index.js (I39): `stripe_payment_intent_id LIKE 'test\_%'` ALI
--       `stripe_checkout_session_id LIKE 'cs\_test\_%'`. Narocila guest liste (internemu vnosu brez denarja) se brisejo, a se stejejo v dnevnik.
--   (b) za narocilo, ki bi ga brisali, obstaja davcni racun (`racuni`; velja za VSA narocila, tudi testna). Za PRAVA (ne testna) narocila ustavijo migracijo tudi spor (`spori`),
--       Stripovo vracilo (`vracila_iz_stripa`) ali vracilo z oznako Stripa v `vracila`; to velja tudi za pravo failed/cancelled narocilo. Spori in Stripova vracila TESTNIH
--       (sandbox) narocil se brisejo skupaj z narocilom in se stejejo v dnevnik.
--   (c) med brisanimi je klub z imenom »Outly« ali uradni profil (`is_official`); narocilo kluba, ki bi ga brisali, pripada dogodku, ki ostane;
--       narocilo, ki ostane, kaze na mizo/paket/kodo/guest listo izbrisanega kluba; neodpovedan dogodek drugega kluba ima izbrisani klub za prizorisce
--       (`venue_club_id`; po brisanju bi ostal brez lokacije). Po brisanju se preveri, da noben klub z is_demo = FALSE ni izginil, da vsi ostali dogodki,
--       narocila in vstopnice se vedno obstajajo in da klub »Outly« (ce je obstajal) ni izginil.
--   Zaradi varoval: ce v produkciji obstaja karkoli od tega, deploy pade z jasnim sporocilom in se ne zgodi nic; takrat najprej odlocita Martin.
--
-- Izbor je po OZNAKI is_demo (ne po imenu): v produkciji jo imajo pet klubov (050). Kar ima oznako, gre; karkoli brez oznake ostane, tudi ce je star ali brez dogodkov.
-- Stevila izbrisanih vrstic po tabelah in seznam klubov, ki ostanejo, gredo v dnevnik deploya (RAISE NOTICE; db/migrate.js jih izpise pod vrstico migracije).
--
-- Na prazni bazi (testi, nova baza) je demo klubov 0 in migracija ne naredi nicesar. Ponovni zagon: ni demo klubov, ne naredi nicesar.
-- Shema se ne spreminja (samo podatki): db/schema.sql ostane enak.

BEGIN;

DO $$
DECLARE
  dk  INT[];      -- id-ji demo klubov
  de  INT[];      -- id-ji dogodkov demo klubov
  o_  BIGINT[];   -- id-ji narocil teh dogodkov
  op_ BIGINT[];   -- med njimi PRAVA (ne testna) narocila
  dt  BIGINT[];   -- id-ji vstopnic teh dogodkov/narocil
  gl  BIGINT[];   -- id-ji guest list teh dogodkov
  ostali_klubi   INT[];
  ostali_dogodki INT[];
  ostala_naroc   BIGINT[];
  ostale_vstop   BIGINT[];
  outly_pred     INT;
  brez_kluba     INT[];
  n BIGINT;
  m BIGINT;
  k RECORD;
BEGIN
  SELECT COALESCE(array_agg(id ORDER BY id), '{}') INTO dk FROM clubs WHERE is_demo;
  IF cardinality(dk) = 0 THEN
    RAISE NOTICE '066: ni demo klubov, nic za brisanje';
    RETURN;
  END IF;

  SELECT COALESCE(array_agg(id ORDER BY id), '{}') INTO de FROM events WHERE club_id = ANY(dk);
  SELECT COALESCE(array_agg(id ORDER BY id), '{}') INTO o_ FROM orders WHERE event_id = ANY(de);
  SELECT COALESCE(array_agg(id ORDER BY id), '{}') INTO op_ FROM orders o
   WHERE o.id = ANY(o_)
     AND NOT (COALESCE(o.stripe_payment_intent_id LIKE 'test\_%', FALSE) OR COALESCE(o.stripe_checkout_session_id LIKE 'cs\_test\_%', FALSE));
  SELECT COALESCE(array_agg(id ORDER BY id), '{}') INTO dt FROM tickets WHERE event_id = ANY(de) OR order_id = ANY(o_);
  SELECT COALESCE(array_agg(id ORDER BY id), '{}') INTO gl FROM guest_lists WHERE event_id = ANY(de);
  RAISE NOTICE '066: demo klubov %, dogodkov %, narocil %, vstopnic %', cardinality(dk), cardinality(de), cardinality(o_), cardinality(dt);

  -- ---------------------------------------------------------------- VAROVALA
  -- (c) Outly in uradni profil
  SELECT COUNT(*) INTO n FROM clubs WHERE id = ANY(dk) AND (lower(btrim(name)) = 'outly' OR is_official);
  IF n > 0 THEN
    RAISE EXCEPTION '066: med demo klubi je klub »Outly« ali uradni profil (is_official), % kluba; takega kluba ne brisem. Najprej odstrani oznako is_demo.', n;
  END IF;

  -- (a) pravo (ne testno) narocilo, ki ni failed/cancelled, na dogodku demo kluba
  SELECT COUNT(*) INTO n FROM orders o
   WHERE o.event_id = ANY(de) AND o.guest_list_id IS NULL AND o.status NOT IN ('failed', 'cancelled')
     AND NOT (COALESCE(o.stripe_payment_intent_id LIKE 'test\_%', FALSE) OR COALESCE(o.stripe_checkout_session_id LIKE 'cs\_test\_%', FALSE));
  IF n > 0 THEN
    RAISE EXCEPTION '066: % pravih (ne testnih) narocil na dogodkih demo klubov (paid/partially_refunded/refunded/pending); to je denar ali obveznost do kupca. Nic ni izbrisano.', n;
  END IF;

  -- (b) racun (vsa narocila); spor, Stripovo vracilo (samo PRAVA narocila: testne brisemo z narocilom)
  SELECT COUNT(*) INTO n FROM racuni WHERE order_id = ANY(o_);
  IF n > 0 THEN RAISE EXCEPTION '066: % davcnih racunov (racuni) za narocila, ki bi jih brisal. Nic ni izbrisano.', n; END IF;
  SELECT COUNT(*) INTO n FROM spori WHERE order_id = ANY(op_);
  IF n > 0 THEN RAISE EXCEPTION '066: % sporov (spori) za prava narocila, ki bi jih brisal. Nic ni izbrisano.', n; END IF;
  SELECT COUNT(*) INTO n FROM vracila_iz_stripa WHERE order_id = ANY(op_);
  IF n > 0 THEN RAISE EXCEPTION '066: % Stripovih vracil (vracila_iz_stripa) za prava narocila, ki bi jih brisal. Nic ni izbrisano.', n; END IF;
  SELECT COUNT(*) INTO n FROM vracila
   WHERE order_id = ANY(op_) AND (stripe_vracilo_id IS NOT NULL OR provizija_vracilo_id IS NOT NULL);
  IF n > 0 THEN RAISE EXCEPTION '066: % vracil z oznako Stripa (vracila.stripe_vracilo_id/provizija_vracilo_id) za prava narocila. Nic ni izbrisano.', n; END IF;

  -- (c) tuje vrstice, ki kazejo na izbrisane
  SELECT COUNT(*) INTO n FROM orders WHERE club_id = ANY(dk) AND event_id <> ALL(de);
  IF n > 0 THEN RAISE EXCEPTION '066: % narocil z club_id demo kluba na dogodku, ki ostane. Nic ni izbrisano.', n; END IF;
  SELECT COUNT(*) INTO n FROM orders o
   WHERE o.id <> ALL(o_) AND (
         o.table_id   IN (SELECT id FROM club_tables     WHERE club_id = ANY(dk))
      OR o.package_id IN (SELECT id FROM bottle_packages WHERE club_id = ANY(dk))
      OR o.promo_code_id IN (SELECT id FROM promo_codes  WHERE club_id = ANY(dk))
      OR o.guest_list_id = ANY(gl));
  IF n > 0 THEN RAISE EXCEPTION '066: % narocil, ki ostanejo, kaze na mizo/paket/kodo/guest listo izbrisanega kluba. Nic ni izbrisano.', n; END IF;
  SELECT COUNT(*) INTO n FROM events WHERE club_id <> ALL(dk) AND venue_club_id = ANY(dk) AND status <> 'cancelled';
  IF n > 0 THEN RAISE EXCEPTION '066: % neodpovedanih dogodkov drugih klubov ima demo klub za prizorisce (venue_club_id); po brisanju bi ostali brez lokacije. Nic ni izbrisano.', n; END IF;

  -- Kar mora ostati (preverimo po brisanju; id-ji, ne vsebina: sprotni nakupi na Outly dogodkih ne smejo podreti migracije).
  SELECT COALESCE(array_agg(id), '{}') INTO ostali_klubi   FROM clubs   WHERE id <> ALL(dk);
  SELECT COALESCE(array_agg(id), '{}') INTO ostali_dogodki FROM events  WHERE id <> ALL(de);
  SELECT COALESCE(array_agg(id), '{}') INTO ostala_naroc   FROM orders  WHERE id <> ALL(o_);
  SELECT COALESCE(array_agg(id), '{}') INTO ostale_vstop   FROM tickets WHERE id <> ALL(dt);
  SELECT COUNT(*) INTO outly_pred FROM clubs WHERE id <> ALL(dk) AND lower(btrim(name)) = 'outly';

  -- Uporabniki, ki po brisanju nimajo vec nobenega kluba (ne brisemo jih).
  SELECT COALESCE(array_agg(DISTINCT u), '{}') INTO brez_kluba FROM (
    SELECT owner_user_id AS u FROM clubs WHERE id = ANY(dk)
    UNION
    SELECT user_id FROM club_members WHERE club_id = ANY(dk)
  ) x
  WHERE NOT EXISTS (SELECT 1 FROM clubs c WHERE c.owner_user_id = x.u AND c.id <> ALL(dk))
    AND NOT EXISTS (SELECT 1 FROM club_members m WHERE m.user_id = x.u AND m.club_id <> ALL(dk));

  -- ---------------------------------------------------------------- BRISANJE (od listov proti korenu)
  DELETE FROM gost_zetoni_vstopnic WHERE ticket_id = ANY(dt);       GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: gost_zetoni_vstopnic %', n;
  DELETE FROM gost_zetoni WHERE order_id = ANY(o_);                 GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: gost_zetoni %', n;
  DELETE FROM ticket_transfers WHERE ticket_id = ANY(dt);           GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: ticket_transfers %', n;
  DELETE FROM guest_list_members WHERE ticket_id = ANY(dt) OR guest_list_id = ANY(gl);
                                                                    GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: guest_list_members %', n;
  DELETE FROM tickets WHERE id = ANY(dt);                           GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: tickets %', n;
  DELETE FROM vracila_iz_stripa WHERE order_id = ANY(o_);           GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: vracila_iz_stripa (testna) %', n;
  DELETE FROM spori WHERE order_id = ANY(o_);                       GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: spori (testni) %', n;
  DELETE FROM vracila WHERE order_id = ANY(o_) OR event_id = ANY(de);
                                                                    GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: vracila %', n;
  DELETE FROM table_service WHERE order_id = ANY(o_) OR event_id = ANY(de) OR club_id = ANY(dk);
                                                                    GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: table_service %', n;
  SELECT COUNT(*) INTO m FROM orders WHERE id = ANY(o_) AND guest_list_id IS NOT NULL;
  DELETE FROM orders WHERE id = ANY(o_);                            GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: orders % (od tega guest lista %)', n, m;
  DELETE FROM guest_lists WHERE id = ANY(gl);                       GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: guest_lists %', n;
  DELETE FROM reports
   WHERE (target_type IN ('club', 'media') AND target_id = ANY(dk)) OR (target_type = 'event' AND target_id = ANY(de));
                                                                    GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: reports %', n;
  UPDATE predlogi_dejanj
     SET stanje = 'potekel', odloceno_at = NOW(), napaka = '066: dogodek/klub je izbrisan (demo)'
   WHERE stanje = 'caka' AND ((cilj_tip = 'event' AND cilj_id = ANY(de)) OR (cilj_tip = 'club' AND cilj_id = ANY(dk)));
                                                                    GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: predlogi_dejanj poteceni %', n;

  -- Vrstice, ki jih odnese kaskada (samo za dnevnik deploya; stevilo PRED brisanjem dogodkov in klubov).
  FOR k IN
    SELECT 'club_tables' AS t, COUNT(*) AS n FROM club_tables WHERE club_id = ANY(dk) OR event_id = ANY(de)
    UNION ALL SELECT 'event_tables', COUNT(*) FROM event_tables WHERE event_id = ANY(de)
    UNION ALL SELECT 'table_holds', COUNT(*) FROM table_holds WHERE event_id = ANY(de)
    UNION ALL SELECT 'bottle_packages', COUNT(*) FROM bottle_packages WHERE club_id = ANY(dk)
    UNION ALL SELECT 'promo_codes', COUNT(*) FROM promo_codes WHERE club_id = ANY(dk)
    UNION ALL SELECT 'promo_code_events', COUNT(*) FROM promo_code_events WHERE event_id = ANY(de)
    UNION ALL SELECT 'club_members', COUNT(*) FROM club_members WHERE club_id = ANY(dk)
    UNION ALL SELECT 'club_invites', COUNT(*) FROM club_invites WHERE club_id = ANY(dk)
    UNION ALL SELECT 'club_follows', COUNT(*) FROM club_follows WHERE club_id = ANY(dk)
    UNION ALL SELECT 'club_event_notifications', COUNT(*) FROM club_event_notifications WHERE event_id = ANY(de)
    UNION ALL SELECT 'event_favorites', COUNT(*) FROM event_favorites WHERE event_id = ANY(de)
    UNION ALL SELECT 'event_interest', COUNT(*) FROM event_interest WHERE event_id = ANY(de)
    UNION ALL SELECT 'odpovedi_dogodkov', COUNT(*) FROM odpovedi_dogodkov WHERE event_id = ANY(de)
    UNION ALL SELECT 'view_counts', COUNT(*) FROM view_counts WHERE club_id = ANY(dk) OR event_id = ANY(de)
    UNION ALL SELECT 'creator_applications (club_id -> NULL)', COUNT(*) FROM creator_applications WHERE club_id = ANY(dk)
    UNION ALL SELECT 'events tujih klubov (venue_club_id/vip_layout_from_club_id -> NULL)', COUNT(*) FROM events
      WHERE club_id <> ALL(dk) AND (venue_club_id = ANY(dk) OR vip_layout_from_club_id = ANY(dk))
  LOOP
    RAISE NOTICE '066: kaskada %: %', k.t, k.n;
  END LOOP;

  DELETE FROM events WHERE id = ANY(de);                            GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: events %', n;
  DELETE FROM clubs WHERE id = ANY(dk);                             GET DIAGNOSTICS n = ROW_COUNT; RAISE NOTICE '066: clubs %', n;

  -- ---------------------------------------------------------------- PREVERJANJE PO BRISANJU
  SELECT COUNT(*) INTO n FROM clubs WHERE is_demo;
  IF n <> 0 THEN RAISE EXCEPTION '066: po brisanju je se % demo klubov', n; END IF;
  SELECT COUNT(*) INTO n FROM clubs WHERE id = ANY(ostali_klubi);
  IF n <> cardinality(ostali_klubi) THEN RAISE EXCEPTION '066: izginil je klub, ki bi moral ostati (% od %)', n, cardinality(ostali_klubi); END IF;
  SELECT COUNT(*) INTO n FROM events WHERE id = ANY(ostali_dogodki);
  IF n <> cardinality(ostali_dogodki) THEN RAISE EXCEPTION '066: izginil je dogodek, ki bi moral ostati (% od %)', n, cardinality(ostali_dogodki); END IF;
  SELECT COUNT(*) INTO n FROM orders WHERE id = ANY(ostala_naroc);
  IF n <> cardinality(ostala_naroc) THEN RAISE EXCEPTION '066: izginilo je narocilo, ki bi moralo ostati (% od %)', n, cardinality(ostala_naroc); END IF;
  SELECT COUNT(*) INTO n FROM tickets WHERE id = ANY(ostale_vstop);
  IF n <> cardinality(ostale_vstop) THEN RAISE EXCEPTION '066: izginila je vstopnica, ki bi morala ostati (% od %)', n, cardinality(ostale_vstop); END IF;
  SELECT COUNT(*) INTO n FROM clubs WHERE lower(btrim(name)) = 'outly';
  IF n < outly_pred THEN RAISE EXCEPTION '066: klub »Outly« je izginil'; END IF;

  RAISE NOTICE '066: ostali so klubi %, dogodki %, narocila %, vstopnice %', cardinality(ostali_klubi), cardinality(ostali_dogodki), cardinality(ostala_naroc), cardinality(ostale_vstop);
  FOR k IN SELECT id, name, is_organizer, is_official FROM clubs ORDER BY id LOOP
    RAISE NOTICE '066: ostal klub id=% ime=% is_organizer=% is_official=%', k.id, k.name, k.is_organizer, k.is_official;
  END LOOP;
  RAISE NOTICE '066: uporabniki brez kluba po brisanju (niso izbrisani): %', brez_kluba;
END $$;

COMMIT;
