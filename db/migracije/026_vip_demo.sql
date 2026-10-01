-- 026_vip_demo.sql
-- Demo VIP mize (Martinovo narocilo 1. 10. 2026): demo klubi iz migracije 022 (Velvet, Nexus, Mirage,
-- Mansion, Olie) dobijo tloris (bar, oder, DJ, plesisce, vhod, WC), 6-10 miz in 4-6 bottle paketov,
-- VIP pa se vklopi na njihovih prihajajocih objavljenih dogodkih - da testerji na telefonu in spletu
-- takoj vidijo, kako izgleda nakup mize.
--
-- Samo ce klub se nima tlorisa (floor_plan IS NULL): klub, ki je tloris ze narisal, ostane nedotaknjen,
-- ponovni zagon ne naredi nicesar. Klubi z drugim imenom in prazna baza (testi) ostanejo nespremenjeni.
-- Vstavlja nove vrstice (mize, paketi); na obstojecih vrsticah samo izpolni NOVA stolpca floor_plan
-- (NULL -> tloris) in events.vip_enabled (privzeto FALSE -> TRUE za prihajajoce dogodke teh klubov).
--
-- Mreza 24 x 16: oder zgoraj na sredini z DJ pultom pred njim, plesisce pod njima, bar ob levi steni,
-- WC zgoraj desno, vhod spodaj, mize ob plesiscu. Cene 200-800 EUR (v centih), 4-10 oseb.

BEGIN;

DO $$
DECLARE
  k RECORD;
  kid INT;
  skupaj INT;
BEGIN
  FOR k IN
    SELECT * FROM (VALUES
      -- ime, stevilo miz (od 10 v predlogi spodaj), stevilo paketov (od 6)
      ('Velvet',  10, 6),
      ('Nexus',    8, 5),
      ('Mirage',   7, 4),
      ('Mansion',  9, 6),
      ('Olie',     6, 4)
    ) AS v(ime, st_miz, st_paketov)
  LOOP
    SELECT c.id INTO kid FROM clubs c WHERE c.name = k.ime AND c.floor_plan IS NULL ORDER BY c.id LIMIT 1;
    CONTINUE WHEN kid IS NULL;

    UPDATE clubs SET floor_plan = '{
      "width": 24, "height": 16,
      "elements": [
        {"type": "stage",      "x": 7,  "y": 0,  "w": 10, "h": 3, "label": ""},
        {"type": "dj",         "x": 10, "y": 3,  "w": 4,  "h": 2, "label": ""},
        {"type": "dancefloor", "x": 7,  "y": 6,  "w": 10, "h": 5, "label": ""},
        {"type": "bar",        "x": 0,  "y": 2,  "w": 3,  "h": 8, "label": ""},
        {"type": "wc",         "x": 21, "y": 0,  "w": 3,  "h": 3, "label": ""},
        {"type": "label",      "x": 18, "y": 3,  "w": 5,  "h": 1, "label": "VIP area"},
        {"type": "entrance",   "x": 9,  "y": 15, "w": 6,  "h": 1, "label": ""}
      ]
    }'::jsonb WHERE id = kid;

    INSERT INTO club_tables (club_id, label, x, y, w, h, shape, seats, price_cents)
    SELECT kid, t.label, t.x, t.y, t.w, t.h, t.shape, t.seats, t.cena
    FROM (VALUES
      (1,  'T1',  4,  3,  2, 2, 'round', 4,  20000),
      (2,  'T2',  4,  6,  2, 2, 'round', 4,  22000),
      (3,  'T3',  4,  9,  2, 2, 'round', 6,  28000),
      (4,  'T4',  18, 5,  2, 2, 'round', 6,  30000),
      (5,  'T5',  18, 8,  2, 2, 'round', 6,  32000),
      (6,  'T6',  21, 5,  2, 2, 'round', 8,  40000),
      (7,  'T7',  21, 8,  2, 2, 'round', 8,  45000),
      (8,  'T8',  8,  12, 3, 2, 'rect',  8,  50000),
      (9,  'T9',  13, 12, 3, 2, 'rect',  10, 65000),
      (10, 'T10', 18, 11, 4, 2, 'rect',  10, 80000)
    ) AS t(zap, label, x, y, w, h, shape, seats, cena)
    WHERE t.zap <= k.st_miz
      AND NOT EXISTS (SELECT 1 FROM club_tables ct WHERE ct.club_id = kid);

    INSERT INTO bottle_packages (club_id, name, description, sort)
    SELECT kid, p.ime, p.opis, p.zap
    FROM (VALUES
      (1, 'Jameson 0,7 l',            '4x Red Bull, 1 l orange juice'),
      (2, 'Absolut Vodka 0,7 l',      '4x Red Bull, 1 l cranberry juice'),
      (3, 'Jack Daniel''s 0,7 l',     '6x Coca-Cola, ice and lemon'),
      (4, 'Hennessy VS 0,7 l',        '4x ginger ale, ice and lime'),
      (5, 'Grey Goose 0,7 l',         '4x Red Bull, 1 l grapefruit juice'),
      (6, 'Moet & Chandon Brut 0,75 l', 'Strawberries and sparklers')
    ) AS p(zap, ime, opis)
    WHERE p.zap <= k.st_paketov
      AND NOT EXISTS (SELECT 1 FROM bottle_packages bp WHERE bp.club_id = kid);

    UPDATE events SET vip_enabled = TRUE
     WHERE club_id = kid AND status = 'published' AND start_at > NOW() AND NOT vip_enabled;
  END LOOP;
END $$;

COMMIT;
