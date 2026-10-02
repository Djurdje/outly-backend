-- Testni podatki za obremenitev (orodja/obremenitev.mjs): 30 klubov, 200 prihajajocih objavljenih dogodkov.
-- SAMO za lokalno bazo po `npm run migrate`. Zavrne vsako bazo, katere ime ne vsebuje »obremenitev« ali »test«.
--   createdb -h localhost -U postgres outly_obremenitev_lj
--   DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly_obremenitev_lj npm run migrate
--   psql postgres://postgres:postgres@localhost:5432/outly_obremenitev_lj -f orodja/obremenitev-podatki.sql
\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN
  IF current_database() !~* '(obremenitev|test)' THEN
    RAISE EXCEPTION 'Zavrnjeno: baza % ni testna (ime mora vsebovati obremenitev ali test).', current_database();
  END IF;
END $$;

INSERT INTO users (email, username, email_verified, role)
VALUES ('seme-obremenitev@outly.si', 'seme_obremenitev', true, 'business')
ON CONFLICT DO NOTHING;

INSERT INTO clubs (owner_user_id, name, description, city, country, address, lat, lng, genres, min_age, instagram, website,
                   logo_url, banner_url, gallery_urls, bar_prices)
SELECT (SELECT id FROM users WHERE email = 'seme-obremenitev@outly.si'),
       'Obremenitev klub ' || g,
       repeat('Opis kluba ' || g || '. Najboljsa glasba v mestu, odlicni koktejli in vrhunsko vzdusje. ', 4),
       (ARRAY['Ljubljana','Maribor','Celje','Koper'])[1 + g % 4], 'SI', 'Ulica ' || g,
       46.05 + (g % 10) * 0.01, 14.50 + (g % 7) * 0.01,
       ARRAY['house','techno','hiphop'], 18, '@klub' || g, 'https://klub' || g || '.example',
       'https://res.cloudinary.com/demo/image/upload/logo' || g || '.jpg', 'https://res.cloudinary.com/demo/image/upload/banner' || g || '.jpg',
       ARRAY['https://res.cloudinary.com/demo/image/upload/g1_' || g || '.jpg', 'https://res.cloudinary.com/demo/image/upload/g2_' || g || '.jpg'],
       '[{"name":"Pivo","price_cents":350},{"name":"Gin tonic","price_cents":700},{"name":"Voda","price_cents":250}]'::jsonb
FROM generate_series(1, 30) g;

INSERT INTO events (club_id, title, description, poster_url, start_at, end_at, min_age, genres, status, ticket_price_cents, capacity)
SELECT (SELECT id FROM clubs WHERE name = 'Obremenitev klub ' || (1 + g % 30)),
       'Obremenitev dogodek ' || g,
       repeat('Opis dogodka ' || g || '. Gostujoci DJ, posebna razsvetljava in presenecenja do jutra. ', 4),
       'https://res.cloudinary.com/demo/image/upload/plakat' || g || '.jpg',
       NOW() + (g || ' hours')::interval * 6, NOW() + (g || ' hours')::interval * 6 + INTERVAL '6 hours', 18,
       ARRAY['house','techno'], 'published', 1500 + (g % 5) * 500, 500
FROM generate_series(1, 200) g;
COMMIT;
