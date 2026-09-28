-- 022_izmisljeni_demo_klubi.sql
-- Demo klubi v produkciji so bili pravi ljubljanski klubi (Cirkus, K4, Cvetlicarna, Square, Nebo)
-- s slikami z njihovih spletnih strani - tega ne smemo kazati (STATE.md "Slike klubov v produkciji
-- so ZA DEMO"). Martin 28. 9. 2026: zamenjaj jih s petimi IZMISLJENIMI klubi (ime, opis, slike,
-- video, cenik bara, kontakt, naslov) in jim dodaj prihajajoce dogodke.
--
-- Kaj naredi, za vsak star klub (najde ga po imenu):
--   1. klubu prepise vse, kar klub sam ureja (id, lastnik, ekipa, sledilci in vstopnice ostanejo);
--   2. zbrise njegove stare dogodke BREZ narocil/vstopnic (priljubljeni, "I'm in", ogledi in obvestila
--      teh dogodkov gredo z njimi - ON DELETE CASCADE); dogodke Z narocili/vstopnicami ohrani
--      (RESTRICT, in vstopnica mora ostati veljavna), le prepise jim naslov, opis in plakat;
--   3. doda 3 nove dogodke (oktober/november 2026).
-- Slike in videi so izmisljeni in gostijo na https://outly.si/demo/<klub>/ (repo outly_webpage).
-- Instagram, spletna stran in telefon so prazni namerno: izmisljen naslov bi lahko kazal na tuj
-- pravi racun/stevilko. E-naslovi so na poddomeni demo.outly.si (nikamor ne dostavijo).
--
-- Varnost: ce ime ustreza vec kot enemu klubu, migracija PADE (vse se povrne), da ne prepise
-- pravega kluba. Ce kluba ni (prazna baza, testi), ga preskoci. Ponoven zagon ne naredi nic,
-- ker starih imen potem ni vec.
-- SPREMINJA PRODUKCIJSKE PODATKE -> merge samo z Martinovim DA (oznaka odobril-martin).

BEGIN;

DO $$
DECLARE
    k_id  INTEGER;
    n     INTEGER;
BEGIN

    -- K4 -> HALOGEN
    SELECT COUNT(*) INTO n FROM clubs WHERE lower(name) ~ '\mk4\M';
    IF n > 1 THEN
        RAISE EXCEPTION '022: ime "K4" ustreza % klubom - ne vem, katerega zamenjati', n;
    END IF;
    SELECT id INTO k_id FROM clubs WHERE lower(name) ~ '\mk4\M';
    IF k_id IS NULL THEN
        RAISE NOTICE '022: klub "K4" ne obstaja - preskocen';
    ELSE
        UPDATE clubs SET
            name          = 'HALOGEN',
            logo_url      = 'https://outly.si/demo/halogen/logo.png',
            banner_url    = 'https://outly.si/demo/halogen/banner.jpg',
            gallery_urls  = ARRAY['https://outly.si/demo/halogen/gallery-1.jpg', 'https://outly.si/demo/halogen/gallery-2.jpg', 'https://outly.si/demo/halogen/gallery-3.jpg']::text[],
            video_url     = 'https://outly.si/demo/halogen/video.mp4',
            description   = 'Ljubljana''s home for uncompromising techno. HALOGEN lives inside a converted 1960s power substation: six-metre ceilings, raw concrete, a hand-tuned four-point sound system and a single room built for dancing. Phones stay in pockets on the floor, the lights stay low and the music runs until the morning.

Open Friday and Saturday from 23:00. Door policy: respect the room and the people in it.',
            contact_email = 'halogen@demo.outly.si',
            contact_phone = '',
            instagram     = '',
            website       = '',
            address       = 'Tovarniška ulica 14',
            city          = 'Ljubljana',
            country       = 'Slovenia',
            lat           = 46.0561,
            lng           = 14.5352,
            min_age       = 18,
            genres        = ARRAY['techno', 'electronic', 'house']::text[],
            bar_prices    = '[{"name":"Draft lager 0.3 l","price_cents":350,"category":"Beer"},{"name":"Draft lager 0.5 l","price_cents":450,"category":"Beer"},{"name":"Craft IPA 0.33 l","price_cents":550,"category":"Beer"},{"name":"Mineral water 0.5 l","price_cents":250,"category":"Soft drinks"},{"name":"Mate 0.5 l","price_cents":400,"category":"Soft drinks"},{"name":"Energy drink","price_cents":400,"category":"Soft drinks"},{"name":"Gin & tonic","price_cents":900,"category":"Long drinks"},{"name":"Vodka & energy","price_cents":900,"category":"Long drinks"},{"name":"Rum & cola","price_cents":850,"category":"Long drinks"},{"name":"Tequila","price_cents":350,"category":"Shots"},{"name":"Jägermeister","price_cents":350,"category":"Shots"},{"name":"Espresso","price_cents":200,"category":"Coffee"}]'::jsonb
        WHERE id = k_id;

        DELETE FROM events e
        WHERE e.club_id = k_id
          AND NOT EXISTS (SELECT 1 FROM orders o WHERE o.event_id = e.id)
          AND NOT EXISTS (SELECT 1 FROM tickets t WHERE t.event_id = e.id);

        UPDATE events SET
            title       = 'HALOGEN Session',
            description = '',
            poster_url  = 'https://outly.si/demo/halogen/banner.jpg',
            genres      = ARRAY['techno', 'electronic', 'house']::text[],
            recap_video_url = ''
        WHERE club_id = k_id;

        INSERT INTO events (club_id, title, description, poster_url, start_at, end_at,
                            min_age, genres, status, ticket_price_cents, currency, capacity)
        VALUES
            (k_id, 'Voltage Ritual', 'HALOGEN opens October with a full night of driving, hypnotic techno. Berlin-based Mara Voss returns for an extended set, Kiro Deltin brings his hardware live show, and residents Anja Stern and Lumen close the night back to back.

Line-up: Mara Voss · Kiro Deltin (live) · Anja Stern b2b Lumen
Doors 23:00 · 18+ · No photos on the dancefloor',
             'https://outly.si/demo/halogen/events/voltage-ritual.jpg',
             '2026-10-02T23:00:00+02:00', '2026-10-03T06:00:00+02:00', 18, ARRAY['techno']::text[], 'published', 1500, 'EUR', 900),
            (k_id, 'Low Frequency Society', 'A night for the heavy end of the spectrum: deep, dubby and relentless. Oskar Hale performs his new live set for the first time in Slovenia, Tessa Rhein plays a four-hour closing set.

Line-up: Oskar Hale (live) · Tessa Rhein · Dunjo
Doors 23:00 · 18+',
             'https://outly.si/demo/halogen/events/low-frequency-society.jpg',
             '2026-10-17T23:00:00+02:00', '2026-10-18T07:00:00+02:00', 18, ARRAY['techno', 'electronic']::text[], 'published', 1800, 'EUR', 900),
            (k_id, 'HALOGEN 6 Years — 12 Hours', 'Six years of HALOGEN, twelve hours of music. Friends of the house and every resident across one long night into morning — the room opens at 22:00 and closes when the last record ends.

Line-up: Mara Voss · Oskar Hale · Nika Brun · Anja Stern · Lumen · Dunjo
Doors 22:00 · 18+ · Limited capacity, buy early',
             'https://outly.si/demo/halogen/events/halogen-6-years.jpg',
             '2026-10-31T22:00:00+01:00', '2026-11-01T10:00:00+01:00', 18, ARRAY['techno', 'electronic', 'house']::text[], 'published', 2500, 'EUR', 900);
    END IF;
    k_id := NULL;

    -- Nebo -> Nocturne
    SELECT COUNT(*) INTO n FROM clubs WHERE lower(name) ~ '\mnebo\M';
    IF n > 1 THEN
        RAISE EXCEPTION '022: ime "Nebo" ustreza % klubom - ne vem, katerega zamenjati', n;
    END IF;
    SELECT id INTO k_id FROM clubs WHERE lower(name) ~ '\mnebo\M';
    IF k_id IS NULL THEN
        RAISE NOTICE '022: klub "Nebo" ne obstaja - preskocen';
    ELSE
        UPDATE clubs SET
            name          = 'Nocturne',
            logo_url      = 'https://outly.si/demo/nocturne/logo.png',
            banner_url    = 'https://outly.si/demo/nocturne/banner.jpg',
            gallery_urls  = ARRAY['https://outly.si/demo/nocturne/gallery-1.jpg', 'https://outly.si/demo/nocturne/gallery-2.jpg', 'https://outly.si/demo/nocturne/gallery-3.jpg']::text[],
            video_url     = 'https://outly.si/demo/nocturne/video.mp4',
            description   = 'Nocturne sits on the twelfth floor above the city centre: a glass-walled lounge, an open-air terrace with the best view of the castle, and a dancefloor that fills up when the sun goes down. Expect house, disco and soulful grooves, a cocktail list built by our own bar team and a crowd that likes to dress up.

Open Thursday to Saturday from 18:00. Smart-casual dress code. Table reservations via the app.',
            contact_email = 'nocturne@demo.outly.si',
            contact_phone = '',
            instagram     = '',
            website       = '',
            address       = 'Slovenska cesta 40, 12th floor',
            city          = 'Ljubljana',
            country       = 'Slovenia',
            lat           = 46.0532,
            lng           = 14.5031,
            min_age       = 21,
            genres        = ARRAY['house', 'rnb', '80s']::text[],
            bar_prices    = '[{"name":"Nocturne Spritz","price_cents":1100,"category":"Signature cocktails"},{"name":"Midnight Negroni","price_cents":1200,"category":"Signature cocktails"},{"name":"Castle View Sour","price_cents":1200,"category":"Signature cocktails"},{"name":"Golden Hour Mule","price_cents":1100,"category":"Signature cocktails"},{"name":"Aperol Spritz","price_cents":900,"category":"Classics"},{"name":"Espresso Martini","price_cents":1100,"category":"Classics"},{"name":"Mojito","price_cents":1000,"category":"Classics"},{"name":"Prosecco (glass)","price_cents":700,"category":"Wine & bubbles"},{"name":"Slovenian white wine (glass)","price_cents":600,"category":"Wine & bubbles"},{"name":"Champagne (bottle)","price_cents":12000,"category":"Wine & bubbles"},{"name":"Bottled lager 0.33 l","price_cents":500,"category":"Beer"},{"name":"Sparkling water 0.75 l","price_cents":450,"category":"Soft drinks"},{"name":"Fresh lemonade","price_cents":450,"category":"Soft drinks"}]'::jsonb
        WHERE id = k_id;

        DELETE FROM events e
        WHERE e.club_id = k_id
          AND NOT EXISTS (SELECT 1 FROM orders o WHERE o.event_id = e.id)
          AND NOT EXISTS (SELECT 1 FROM tickets t WHERE t.event_id = e.id);

        UPDATE events SET
            title       = 'Nocturne Session',
            description = '',
            poster_url  = 'https://outly.si/demo/nocturne/banner.jpg',
            genres      = ARRAY['house', 'rnb', '80s']::text[],
            recap_video_url = ''
        WHERE club_id = k_id;

        INSERT INTO events (club_id, title, description, poster_url, start_at, end_at,
                            min_age, genres, status, ticket_price_cents, currency, capacity)
        VALUES
            (k_id, 'Sunset Sessions: Terrace Closing', 'The last open-air night of the season. We start with the sunset over the castle and go deep into the night with warm, melodic house on the terrace and inside.

Line-up: Leon Marin · Sofia Kral · Nocturne residents
From 18:00 · 21+ · Smart-casual',
             'https://outly.si/demo/nocturne/events/terrace-closing.jpg',
             '2026-10-03T18:00:00+02:00', '2026-10-04T02:00:00+02:00', 21, ARRAY['house']::text[], 'published', 1200, 'EUR', 450),
            (k_id, 'Disco Nocturne', 'Mirror balls, strings and basslines. The Velour Brothers dig into rare disco, boogie and French house, Ema Sol warms up with Italo and nu-disco.

Line-up: The Velour Brothers · Ema Sol
Doors 22:00 · 21+',
             'https://outly.si/demo/nocturne/events/disco-nocturne.jpg',
             '2026-10-16T22:00:00+02:00', '2026-10-17T04:00:00+02:00', 21, ARRAY['house', '80s']::text[], 'published', 1500, 'EUR', 450),
            (k_id, 'Midnight Soul', 'R&B, neo-soul and soulful house, with live vocals from Mila Reyes over Ayo Lane''s set. A slower, warmer night high above the city.

Line-up: Ayo Lane · Mila Reyes (live vocals) · Leon Marin
Doors 22:00 · 21+ · Smart-casual',
             'https://outly.si/demo/nocturne/events/midnight-soul.jpg',
             '2026-11-07T22:00:00+01:00', '2026-11-08T04:00:00+01:00', 21, ARRAY['rnb', 'house']::text[], 'published', 1500, 'EUR', 450);
    END IF;
    k_id := NULL;

    -- Square -> Bazen
    SELECT COUNT(*) INTO n FROM clubs WHERE lower(name) ~ '\msquare\M';
    IF n > 1 THEN
        RAISE EXCEPTION '022: ime "Square" ustreza % klubom - ne vem, katerega zamenjati', n;
    END IF;
    SELECT id INTO k_id FROM clubs WHERE lower(name) ~ '\msquare\M';
    IF k_id IS NULL THEN
        RAISE NOTICE '022: klub "Square" ne obstaja - preskocen';
    ELSE
        UPDATE clubs SET
            name          = 'Bazen',
            logo_url      = 'https://outly.si/demo/bazen/logo.png',
            banner_url    = 'https://outly.si/demo/bazen/banner.jpg',
            gallery_urls  = ARRAY['https://outly.si/demo/bazen/gallery-1.jpg', 'https://outly.si/demo/bazen/gallery-2.jpg', 'https://outly.si/demo/bazen/gallery-3.jpg']::text[],
            video_url     = 'https://outly.si/demo/bazen/video.mp4',
            description   = 'Bazen is a hip hop club built inside a 1970s public swimming pool. The dancefloor is the old pool itself — tiles, lane lines and ladders still in place — with the DJ booth on the diving platform. Hip hop, trap, R&B and afrobeats every weekend, local crews and international guests.

Open Thursday to Saturday from 23:00. Dress code: come as you are, but come fresh.',
            contact_email = 'bazen@demo.outly.si',
            contact_phone = '',
            instagram     = '',
            website       = '',
            address       = 'Celovška cesta 108',
            city          = 'Ljubljana',
            country       = 'Slovenia',
            lat           = 46.0668,
            lng           = 14.4925,
            min_age       = 18,
            genres        = ARRAY['hiphop', 'trap', 'rnb', 'afrobeat']::text[],
            bar_prices    = '[{"name":"Bottled lager 0.33 l","price_cents":400,"category":"Beer"},{"name":"Draft lager 0.5 l","price_cents":450,"category":"Beer"},{"name":"Hennessy & cola","price_cents":1100,"category":"Long drinks"},{"name":"Whisky & cola","price_cents":900,"category":"Long drinks"},{"name":"Vodka & cranberry","price_cents":850,"category":"Long drinks"},{"name":"Deep End (blue lagoon)","price_cents":900,"category":"Cocktails"},{"name":"Pina Colada","price_cents":900,"category":"Cocktails"},{"name":"Tequila","price_cents":350,"category":"Shots"},{"name":"Sambuca","price_cents":300,"category":"Shots"},{"name":"Cola 0.33 l","price_cents":350,"category":"Soft drinks"},{"name":"Energy drink","price_cents":400,"category":"Soft drinks"},{"name":"Vodka 0.7 l + 4 mixers","price_cents":12000,"category":"Bottle service"},{"name":"Cognac 0.7 l + 4 mixers","price_cents":16000,"category":"Bottle service"}]'::jsonb
        WHERE id = k_id;

        DELETE FROM events e
        WHERE e.club_id = k_id
          AND NOT EXISTS (SELECT 1 FROM orders o WHERE o.event_id = e.id)
          AND NOT EXISTS (SELECT 1 FROM tickets t WHERE t.event_id = e.id);

        UPDATE events SET
            title       = 'Bazen Session',
            description = '',
            poster_url  = 'https://outly.si/demo/bazen/banner.jpg',
            genres      = ARRAY['hiphop', 'trap', 'rnb', 'afrobeat']::text[],
            recap_video_url = ''
        WHERE club_id = k_id;

        INSERT INTO events (club_id, title, description, poster_url, start_at, end_at,
                            min_age, genres, status, ticket_price_cents, currency, capacity)
        VALUES
            (k_id, 'DEEP END — Hip Hop Night', 'Our weekly hip hop night in the deep end of the pool. Classics, new heat and everything in between from residents DJ Kalamar and Nuri.

Line-up: DJ Kalamar · Nuri · Bazen Sound
Doors 23:00 · 18+',
             'https://outly.si/demo/bazen/events/deep-end.jpg',
             '2026-10-01T23:00:00+02:00', '2026-10-02T05:00:00+02:00', 18, ARRAY['hiphop', 'rap']::text[], 'published', 1000, 'EUR', 700),
            (k_id, 'Afro Splash', 'Afrobeats, amapiano and R&B all night. Kofi Mensa flies in from Vienna, Selah brings the vocals and the energy.

Line-up: Kofi Mensa · Selah · DJ Kalamar
Doors 23:00 · 18+',
             'https://outly.si/demo/bazen/events/afro-splash.jpg',
             '2026-10-10T23:00:00+02:00', '2026-10-11T05:00:00+02:00', 18, ARRAY['afrobeat', 'rnb']::text[], 'published', 1200, 'EUR', 700),
            (k_id, 'No Lifeguard', 'The loudest night of the month. Rino Vega performs live with his full crew, followed by a trap and drill set from Mala Tina.

Line-up: Rino Vega (live) · Mala Tina · Nuri
Doors 23:00 · 18+',
             'https://outly.si/demo/bazen/events/no-lifeguard.jpg',
             '2026-10-23T23:00:00+02:00', '2026-10-24T05:00:00+02:00', 18, ARRAY['trap', 'rap', 'hiphop']::text[], 'published', 1200, 'EUR', 700);
    END IF;
    k_id := NULL;

    -- Cirkus -> Orbita
    SELECT COUNT(*) INTO n FROM clubs WHERE lower(name) ~ '\mcirkus\M';
    IF n > 1 THEN
        RAISE EXCEPTION '022: ime "Cirkus" ustreza % klubom - ne vem, katerega zamenjati', n;
    END IF;
    SELECT id INTO k_id FROM clubs WHERE lower(name) ~ '\mcirkus\M';
    IF k_id IS NULL THEN
        RAISE NOTICE '022: klub "Cirkus" ne obstaja - preskocen';
    ELSE
        UPDATE clubs SET
            name          = 'Orbita',
            logo_url      = 'https://outly.si/demo/orbita/logo.png',
            banner_url    = 'https://outly.si/demo/orbita/banner.jpg',
            gallery_urls  = ARRAY['https://outly.si/demo/orbita/gallery-1.jpg', 'https://outly.si/demo/orbita/gallery-2.jpg', 'https://outly.si/demo/orbita/gallery-3.jpg']::text[],
            video_url     = 'https://outly.si/demo/orbita/video.mp4',
            description   = 'Orbita is Ljubljana''s biggest dancefloor: two rooms, a 360° LED ring above the main floor and a playlist everybody knows the words to. Pop, throwback hits from the 80s, 90s and 2000s, and themed nights that people dress up for.

Open Thursday to Saturday from 22:00. Birthday and group packages on request.',
            contact_email = 'orbita@demo.outly.si',
            contact_phone = '',
            instagram     = '',
            website       = '',
            address       = 'Dunajska cesta 158',
            city          = 'Ljubljana',
            country       = 'Slovenia',
            lat           = 46.0739,
            lng           = 14.5118,
            min_age       = 18,
            genres        = ARRAY['pop', '2000s', '90s', '80s']::text[],
            bar_prices    = '[{"name":"Draft lager 0.3 l","price_cents":300,"category":"Beer"},{"name":"Draft lager 0.5 l","price_cents":400,"category":"Beer"},{"name":"Vodka & juice","price_cents":700,"category":"Long drinks"},{"name":"Gin & tonic","price_cents":800,"category":"Long drinks"},{"name":"Rum & cola","price_cents":750,"category":"Long drinks"},{"name":"Orbita Sunrise","price_cents":800,"category":"Cocktails"},{"name":"Sex on the Beach","price_cents":800,"category":"Cocktails"},{"name":"Orbita shot (house)","price_cents":250,"category":"Shots"},{"name":"Tequila","price_cents":300,"category":"Shots"},{"name":"5 shots tower","price_cents":1200,"category":"Shots"},{"name":"Water 0.5 l","price_cents":250,"category":"Soft drinks"},{"name":"Juice 0.25 l","price_cents":300,"category":"Soft drinks"}]'::jsonb
        WHERE id = k_id;

        DELETE FROM events e
        WHERE e.club_id = k_id
          AND NOT EXISTS (SELECT 1 FROM orders o WHERE o.event_id = e.id)
          AND NOT EXISTS (SELECT 1 FROM tickets t WHERE t.event_id = e.id);

        UPDATE events SET
            title       = 'Orbita Session',
            description = '',
            poster_url  = 'https://outly.si/demo/orbita/banner.jpg',
            genres      = ARRAY['pop', '2000s', '90s', '80s']::text[],
            recap_video_url = ''
        WHERE club_id = k_id;

        INSERT INTO events (club_id, title, description, poster_url, start_at, end_at,
                            min_age, genres, status, ticket_price_cents, currency, capacity)
        VALUES
            (k_id, 'Throwback Thursday: 2000s Only', 'Low-rise jeans optional, singing along mandatory. Nothing but hits from 2000–2009 on both floors.

DJs: DJ Pixel · Maja Flash
Doors 22:00 · 18+ · Free entry before 23:00',
             'https://outly.si/demo/orbita/events/throwback-2000s.jpg',
             '2026-10-08T22:00:00+02:00', '2026-10-09T04:00:00+02:00', 18, ARRAY['2000s', 'pop']::text[], 'published', 800, 'EUR', 1200),
            (k_id, 'Neon 80s', 'Synths, shoulder pads and the biggest choruses of the decade. Best neon outfit wins a table for four.

DJs: Retro Rok · Synthia
Doors 22:00 · 18+',
             'https://outly.si/demo/orbita/events/neon-80s.jpg',
             '2026-10-24T22:00:00+02:00', '2026-10-25T05:00:00+01:00', 18, ARRAY['80s', 'pop']::text[], 'published', 1000, 'EUR', 1200),
            (k_id, 'Halloween: Lost in Space', 'Orbita''s Halloween party goes to outer space: costume contest at 01:00, space-themed decor across both rooms and pop hits from the 90s to today.

DJs: DJ Pixel · Retro Rok · Maja Flash
Doors 22:00 · 18+ · Costume strongly encouraged',
             'https://outly.si/demo/orbita/events/lost-in-space.jpg',
             '2026-10-31T22:00:00+01:00', '2026-11-01T05:00:00+01:00', 18, ARRAY['pop', '90s', '2000s']::text[], 'published', 1500, 'EUR', 1200);
    END IF;
    k_id := NULL;

    -- Cvetličarna -> Kovačnica
    SELECT COUNT(*) INTO n FROM clubs WHERE (lower(name) LIKE '%cvetli%' OR lower(name) LIKE '%cvetlicarna%');
    IF n > 1 THEN
        RAISE EXCEPTION '022: ime "Cvetličarna" ustreza % klubom - ne vem, katerega zamenjati', n;
    END IF;
    SELECT id INTO k_id FROM clubs WHERE (lower(name) LIKE '%cvetli%' OR lower(name) LIKE '%cvetlicarna%');
    IF k_id IS NULL THEN
        RAISE NOTICE '022: klub "Cvetličarna" ne obstaja - preskocen';
    ELSE
        UPDATE clubs SET
            name          = 'Kovačnica',
            logo_url      = 'https://outly.si/demo/kovacnica/logo.png',
            banner_url    = 'https://outly.si/demo/kovacnica/banner.jpg',
            gallery_urls  = ARRAY['https://outly.si/demo/kovacnica/gallery-1.jpg', 'https://outly.si/demo/kovacnica/gallery-2.jpg', 'https://outly.si/demo/kovacnica/gallery-3.jpg']::text[],
            video_url     = 'https://outly.si/demo/kovacnica/video.mp4',
            description   = 'Kovačnica is a live music venue in a 19th-century blacksmith''s forge. Brick walls, iron beams, a proper stage and a PA that does justice to loud guitars. Rock, punk, metal and hardcore — local bands, touring acts and the occasional all-day fest.

Concerts from Thursday to Sunday, doors usually at 20:00. Earplugs at the bar, free.',
            contact_email = 'kovacnica@demo.outly.si',
            contact_phone = '',
            instagram     = '',
            website       = '',
            address       = 'Poljanska cesta 67',
            city          = 'Ljubljana',
            country       = 'Slovenia',
            lat           = 46.0497,
            lng           = 14.5263,
            min_age       = 16,
            genres        = ARRAY['rock', 'punk', 'metal', 'hardcore']::text[],
            bar_prices    = '[{"name":"Draft lager 0.5 l","price_cents":380,"category":"Beer"},{"name":"Dark lager 0.5 l","price_cents":420,"category":"Beer"},{"name":"Local craft pale ale 0.5 l","price_cents":500,"category":"Beer"},{"name":"Cider 0.33 l","price_cents":450,"category":"Beer"},{"name":"Whiskey 0.03 l","price_cents":400,"category":"Spirits"},{"name":"Plum brandy (slivovka) 0.03 l","price_cents":300,"category":"Spirits"},{"name":"Jägermeister 0.03 l","price_cents":350,"category":"Spirits"},{"name":"Whiskey & cola","price_cents":750,"category":"Long drinks"},{"name":"Cola 0.33 l","price_cents":300,"category":"Soft drinks"},{"name":"Tap water","price_cents":0,"category":"Soft drinks"},{"name":"Kovačnica T-shirt","price_cents":2000,"category":"Merch"}]'::jsonb
        WHERE id = k_id;

        DELETE FROM events e
        WHERE e.club_id = k_id
          AND NOT EXISTS (SELECT 1 FROM orders o WHERE o.event_id = e.id)
          AND NOT EXISTS (SELECT 1 FROM tickets t WHERE t.event_id = e.id);

        UPDATE events SET
            title       = 'Kovačnica Session',
            description = '',
            poster_url  = 'https://outly.si/demo/kovacnica/banner.jpg',
            genres      = ARRAY['rock', 'punk', 'metal', 'hardcore']::text[],
            recap_video_url = ''
        WHERE club_id = k_id;

        INSERT INTO events (club_id, title, description, poster_url, start_at, end_at,
                            min_age, genres, status, ticket_price_cents, currency, capacity)
        VALUES
            (k_id, 'Rust & Thunder: Local Heroes', 'Three of the best loud bands in the country on one bill. Železni Konj headline with songs from their new album.

Bands: Železni Konj · Hollow Anvil · Kislina
Doors 20:00 · First band 20:45 · 16+',
             'https://outly.si/demo/kovacnica/events/rust-and-thunder.jpg',
             '2026-10-09T20:00:00+02:00', '2026-10-10T01:00:00+02:00', 16, ARRAY['rock', 'punk']::text[], 'published', 1200, 'EUR', 400),
            (k_id, 'Sunday Hardcore Matinee', 'An early show for everyone who has work on Monday. Fast, loud and done by ten.

Bands: Brez Milosti · Short Fuse · Grom 88
Doors 17:00 · 16+',
             'https://outly.si/demo/kovacnica/events/hardcore-matinee.jpg',
             '2026-10-18T17:00:00+02:00', '2026-10-18T22:00:00+02:00', 16, ARRAY['hardcore', 'punk']::text[], 'published', 1000, 'EUR', 400),
            (k_id, 'Forge Fest — Heavy Metal Night', 'Our yearly metal night: four bands, eight hours, one very hot forge. Iron Veil headline their only Slovenian show this year.

Bands: Iron Veil · Crna Kovina · Ashbound · Morana
Doors 18:00 · 16+',
             'https://outly.si/demo/kovacnica/events/forge-fest.jpg',
             '2026-11-14T18:00:00+01:00', '2026-11-15T02:00:00+01:00', 16, ARRAY['metal']::text[], 'published', 2000, 'EUR', 400);
    END IF;
    k_id := NULL;
END
$$;

COMMIT;
