-- 024_dogodki_velvet.sql
-- Trije prihajajoci dogodki kluba Velvet s plakati od Martina (28. 9. 2026). Plakati gostujejo
-- na outly.si (repo outly_webpage, assets/events/*.jpg). Datumi so tisti, ki so natisnjeni na
-- plakatih (12. 10. 2026, 26. 4. 2027, 21. 6. 2027 ob 22:00 po ljubljanskem casu).
-- Vstavi samo, ce klub Velvet obstaja in dogodka z istim naslovom se nima (na prazni bazi nic).

BEGIN;

INSERT INTO events (club_id, title, description, poster_url, start_at, end_at, min_age, genres, status,
                    ticket_price_cents, currency, capacity, sold_count)
SELECT c.id, v.naslov, v.opis, v.plakat,
       v.zacetek AT TIME ZONE 'Europe/Ljubljana',
       (v.zacetek + INTERVAL '6 hours') AT TIME ZONE 'Europe/Ljubljana',
       18, v.zanri, 'published', v.cena, 'EUR', v.kapaciteta, 0
FROM clubs c
CROSS JOIN (VALUES
  ('Velvet Nights',
   'Good music, good people. House, R&B and club classics all night. Line up: Lea More, Marko V., Nina Kay.',
   'https://outly.si/assets/events/velvet-nights.jpg', TIMESTAMP '2026-10-12 22:00',
   ARRAY['house', 'rnb'], 1500, 500),
  ('Crni Cerak - Live koncert',
   'Live concert of Crni Cerak at Velvet Night Club. Table reservations by phone.',
   'https://outly.si/assets/events/crni-cerak.jpg', TIMESTAMP '2027-06-21 22:00',
   ARRAY['rap', 'balkan'], 2500, 600),
  ('Lumen - Live koncert',
   'Live concert of Lumen. Support: DJ Raze and DJ Timo.',
   'https://outly.si/assets/events/lumen.jpg', TIMESTAMP '2027-04-26 22:00',
   ARRAY['pop', 'balkan'], 2000, 500)
) AS v(naslov, opis, plakat, zacetek, zanri, cena, kapaciteta)
WHERE c.name = 'Velvet'
  AND NOT EXISTS (SELECT 1 FROM events e WHERE e.club_id = c.id AND e.title = v.naslov);

COMMIT;
