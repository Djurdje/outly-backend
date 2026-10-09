-- 039_razpored_dogodka.sql
-- RAZPORED VIP MIZ PO DOGODKU ZA ORGANIZATORJE (Martin, 9. 10. 2026, »naredi kot ti hoces«; issue #175).
-- Organizator (clubs.is_organizer, 037) nima lastne dvorane, zato pri dogodku izbere vir razporeda VIP miz:
--   'club'  = tloris kluba prodajalca (clubs.floor_plan + club_tables z event_id IS NULL), kot doslej;
--   'event' = razpored TEGA dogodka: kopija tlorisa in miz kluba gostitelja (events.venue_club_id) ali lasten narisan tloris.
-- Paketi steklenic in denar ostanejo pri prodajalcu (events.club_id), narocila/vstopnice/sken/strezba se ne spremenijo:
-- mize dogodka so vrstice v club_tables z event_id, club_id = events.club_id (I13 velja nespremenjen).
--
-- 1) club_tables.event_id: NULL = miza kluba (kot doslej), sicer miza razporeda tega dogodka (ON DELETE CASCADE: dogodek z narocili
--    se tako ali tako ne da izbrisati, orders.event_id in orders.table_id sta RESTRICT).
-- 2) Unikatnost oznake: obstojeci indeks club_tables_label_key je veljal za VSE mize kluba, torej bi dve mizi »T1« razlicnih dogodkov
--    organizatorja trcili. Zamenjamo ga z delnim (samo klubske mize) + nov delni indeks po dogodku. Podatkov ne spreminja
--    (do zdaj ni mize z event_id, zato vsaka obstojeca vrstica ostane pod obsegom starega indeksa).
-- 3) events.vip_layout_source ('club' | 'event', privzeto 'club'), events.floor_plan (JSONB, tloris dogodka), events.vip_layout_from_club_id
--    (iz katerega kluba je kopija, samo informativno; ob izbrisu kluba NULL).
--
-- Samo DODAJANJE (+ zamenjava enega indeksa brez spremembe podatkov); obstojeci podatki in odgovori se ne spremenijo.

BEGIN;

ALTER TABLE club_tables
    ADD COLUMN IF NOT EXISTS event_id INTEGER REFERENCES events(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS club_tables_event_idx
    ON club_tables (event_id) WHERE event_id IS NOT NULL;

-- Oznaka mize: klubske mize (event_id IS NULL) so unikatne po klubu, mize dogodka po dogodku; obakrat samo aktivne, brez razlike velikih in malih crk.
DROP INDEX IF EXISTS club_tables_label_key;
CREATE UNIQUE INDEX club_tables_label_key
    ON club_tables (club_id, lower(label)) WHERE event_id IS NULL AND archived_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS club_tables_event_label_key
    ON club_tables (event_id, lower(label)) WHERE event_id IS NOT NULL AND archived_at IS NULL;

ALTER TABLE events
    ADD COLUMN IF NOT EXISTS vip_layout_source       TEXT    NOT NULL DEFAULT 'club',
    ADD COLUMN IF NOT EXISTS floor_plan              JSONB,
    ADD COLUMN IF NOT EXISTS vip_layout_from_club_id INTEGER REFERENCES clubs(id) ON DELETE SET NULL;

-- CHECK-a dodamo samo, ce ju se ni (ponovni zagon); vse obstojece vrstice imajo 'club' in NULL, zato ju pogoja ne zadeneta.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'events_vip_layout_source_chk' AND conrelid = 'events'::regclass) THEN
        ALTER TABLE events ADD CONSTRAINT events_vip_layout_source_chk CHECK (vip_layout_source IN ('club', 'event'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'events_floor_plan_chk' AND conrelid = 'events'::regclass) THEN
        ALTER TABLE events ADD CONSTRAINT events_floor_plan_chk CHECK (floor_plan IS NULL OR jsonb_typeof(floor_plan) = 'object');
    END IF;
END $$;

COMMENT ON COLUMN club_tables.event_id IS 'NULL = miza kluba; sicer miza razporeda tega dogodka (039), club_id = events.club_id. event_tables (izjeme) veljajo samo za mize z event_id IS NULL.';
COMMENT ON COLUMN events.vip_layout_source IS 'Vir razporeda VIP miz (039): club = tloris kluba prodajalca, event = razpored dogodka (events.floor_plan + club_tables WHERE event_id = id).';
COMMENT ON COLUMN events.floor_plan IS 'Tloris razporeda dogodka (039), enaka oblika kot clubs.floor_plan. Pomemben samo pri vip_layout_source = event.';
COMMENT ON COLUMN events.vip_layout_from_club_id IS 'Klub, iz katerega je kopija razporeda (039; posnetek, poznejse spremembe kluba ne vplivajo). Samo informativno.';

COMMIT;
