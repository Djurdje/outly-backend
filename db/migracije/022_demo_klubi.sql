-- 022_demo_klubi.sql
-- Demo klubi (Martin, 28. 9. 2026): obstojece klube NE brisemo, ampak jih preimenujemo v
-- izmisljena imena in jim izpolnimo vse podatke, da je aplikacija za testerje polna.
-- Do zdaj so imeli imena pravih ljubljanskih klubov (Cirkus, K4, Cvetlicarna, Square, Nebo).
--
--   * Klub z najvec dogodki postane "Velvet", ostali po stevilu dogodkov (izenacenje: starejsi id)
--     "Nexus", "Mirage", "Mansion", "Olie". Klubi nad petim ostanejo nespremenjeni.
--   * Vsak dobi opis, telefon, e-naslov (@example.com - ne gre nikamor), Instagram, naslov in
--     koordinate v centru Ljubljane, zanr "balkan" (dodan, obstojeci zanri ostanejo),
--     cenik bara (samo ce ga klub se nima).
--   * Vsak klub dobi dogodke do skupaj 3 koncanih ("Popular" na strani kluba, po sold_count) in
--     3 prihajajocih ("Coming Soon", najkasnejsi konec februarja 2027 = ~5 mesecev). Obstojeci
--     dogodki, narocila in vstopnice ostanejo nedotaknjeni. Plakat novega dogodka = plakat
--     obstojecega dogodka istega kluba (ali galerija/pasica kluba), brez novih zunanjih slik.
--
-- Slike (logotipi, galerije, plakati) ostanejo stare demo slike - pred pravim zagonom jih
-- zamenjajo slike klubov (glej STATE.md). Na prazni bazi (testi, nova baza) ne naredi nicesar.

BEGIN;

DO $$
DECLARE
  d RECORD;
  kid INT;
  i INT;
  manjka INT;
  plakat TEXT;
  zacetek TIMESTAMPTZ;
BEGIN
  FOR d IN
    SELECT * FROM (VALUES
      (1, 'Velvet',
          'Velvet is the late-night heart of the old town: a velvet-dark room, a big sound system and the best Balkan nights in Ljubljana. Live bands on Fridays, DJs until the lights come on on Saturdays. VIP tables by reservation.',
          '+386 1 620 41 10', 'velvet@example.com', 'velvet.ljubljana',
          'Copova ulica 12', 46.05190::float8, 14.50280::float8),
      (2, 'Nexus',
          'Nexus is an industrial club on the edge of the centre with two floors: Balkan hits upstairs, turbo-folk classics downstairs. Known for packed weekends, a long bar and friendly door staff.',
          '+386 1 620 41 20', 'nexus@example.com', 'nexus.club.lj',
          'Slovenska cesta 36', 46.05330, 14.50480),
      (3, 'Mirage',
          'Mirage is a mirror-lined club by the river with a glowing dance floor and Balkan party nights every weekend. Great cocktails, a small terrace and table service for groups.',
          '+386 1 620 41 30', 'mirage@example.com', 'mirage.ljubljana',
          'Cankarjevo nabrezje 7', 46.05020, 14.50560),
      (4, 'Mansion',
          'Mansion is set in an old city house with three rooms, chandeliers and a courtyard. Weekends are all about Balkan live music, sing-along hits and bottle service at private tables.',
          '+386 1 620 41 40', 'mansion@example.com', 'mansion.lj',
          'Gosposka ulica 9', 46.04870, 14.50370),
      (5, 'Olie',
          'Olie is a cosy club near Preseren Square with a warm, packed dance floor. Expect Balkan pop, folk remixes and guest singers, plus happy hour before midnight.',
          '+386 1 620 41 50', 'olie@example.com', 'olie.club',
          'Trubarjeva cesta 15', 46.05210, 14.50770)
    ) AS v(rn, ime, opis, telefon, email, insta, naslov, lat, lng)
  LOOP
    SELECT c.id INTO kid FROM (
      SELECT c2.id, ROW_NUMBER() OVER (
        ORDER BY (SELECT COUNT(*) FROM events e WHERE e.club_id = c2.id) DESC, c2.id) AS rn
      FROM clubs c2
    ) c WHERE c.rn = d.rn;
    CONTINUE WHEN kid IS NULL;

    UPDATE clubs SET
      name          = d.ime,
      description   = d.opis,
      contact_phone = d.telefon,
      contact_email = d.email,
      instagram     = d.insta,
      address       = d.naslov,
      city          = 'Ljubljana',
      country       = 'Slovenia',
      lat           = d.lat,
      lng           = d.lng,
      min_age       = 18,
      genres        = CASE WHEN 'balkan' = ANY(genres) THEN genres ELSE array_append(genres, 'balkan') END,
      bar_prices    = CASE WHEN jsonb_array_length(bar_prices) > 0 THEN bar_prices ELSE
        '[{"name":"Beer 0.5 l","price_cents":450,"category":"Beer"},
          {"name":"Rakija","price_cents":350,"category":"Shots"},
          {"name":"Gin tonic","price_cents":900,"category":"Cocktails"},
          {"name":"Aperol spritz","price_cents":800,"category":"Cocktails"},
          {"name":"Vodka Red Bull","price_cents":1000,"category":"Long drinks"},
          {"name":"Water 0.5 l","price_cents":250,"category":"Soft drinks"},
          {"name":"Bottle of vodka (table)","price_cents":12000,"category":"Bottles"}]'::jsonb END
    WHERE id = kid;

    -- Plakat za nove dogodke: prvi obstojeci plakat kluba, sicer galerija/pasica/logo.
    SELECT COALESCE(
      (SELECT poster_url FROM events WHERE club_id = kid AND poster_url <> '' ORDER BY start_at DESC LIMIT 1),
      (SELECT NULLIF(gallery_urls[1], '') FROM clubs WHERE id = kid),
      (SELECT NULLIF(banner_url, '') FROM clubs WHERE id = kid),
      (SELECT logo_url FROM clubs WHERE id = kid),
      '') INTO plakat;

    -- Koncani (Popular): dopolni do 3.
    SELECT 3 - COUNT(*) INTO manjka FROM events
     WHERE club_id = kid AND status = 'published' AND COALESCE(end_at, start_at + INTERVAL '8 hours') <= NOW();
    FOR i IN 1..GREATEST(manjka, 0) LOOP
      -- 5., 12., 19. september 2026 (+ dan zamika po klubu), ob 23:00 po ljubljanskem casu.
      zacetek := (TIMESTAMP '2026-09-05 23:00' + ((i - 1) * 7 + d.rn - 1) * INTERVAL '1 day') AT TIME ZONE 'Europe/Ljubljana';
      INSERT INTO events (club_id, title, description, poster_url, start_at, end_at, min_age, genres, status,
                          ticket_price_cents, currency, capacity, sold_count)
      VALUES (kid,
              (ARRAY['Balkan Night', 'Kafana Classics', 'Turbo Folk Fever'])[i] || ' @ ' || d.ime,
              'A sold-out night of Balkan hits, live band and DJs until 5 am.',
              plakat, zacetek, zacetek + INTERVAL '6 hours', 18, ARRAY['balkan'], 'published',
              1000 + i * 200, 'EUR', 400, 400 - i * 60 - d.rn * 10);
    END LOOP;

    -- Prihajajoci (Coming Soon): dopolni do 3, oktober 2026 - februar 2027.
    SELECT 3 - COUNT(*) INTO manjka FROM events
     WHERE club_id = kid AND status = 'published' AND start_at > NOW();
    FOR i IN 1..GREATEST(manjka, 0) LOOP
      zacetek := ((ARRAY[TIMESTAMP '2026-10-16 23:00', TIMESTAMP '2026-12-18 23:00', TIMESTAMP '2027-02-19 23:00'])[i]
                  + (d.rn - 1) * INTERVAL '1 day') AT TIME ZONE 'Europe/Ljubljana';
      INSERT INTO events (club_id, title, description, poster_url, start_at, end_at, min_age, genres, status,
                          ticket_price_cents, currency, capacity, sold_count)
      VALUES (kid,
              (ARRAY['Balkan Friday', 'Winter Balkan Fest', 'Carnival Balkan Party'])[i] || ' @ ' || d.ime,
              'Balkan pop, folk remixes and a live band on stage. Doors 23:00, VIP tables by reservation.',
              plakat, zacetek, zacetek + INTERVAL '6 hours', 18, ARRAY['balkan'], 'published',
              1200 + i * 300, 'EUR', 500, 0);
    END LOOP;
  END LOOP;
END $$;

COMMIT;
