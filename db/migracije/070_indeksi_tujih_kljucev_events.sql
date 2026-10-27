-- 070_indeksi_tujih_kljucev_events.sql
-- INDEKS ZA TUJI KLJUC EVENTS (issue #374): samo DODAJANJE indeksa, brez UPDATE/DELETE podatkov.
-- Del razdelitve 068–072 (issue #374, STATE.md past 3b, najdba pregleda PR #376): glej uvod v 068_indeksi_tujih_kljucev.sql (zakaj, popis tabel, ki se pisejo skupaj).
-- Ta migracija zaklene SAMO: events.
--
-- Ločena: nakup piše orders, sprožilec rezerviraj_zalogo/sprosti_zalogo pa nato še events (UPDATE sold_count); PATCH /events/:id + prekliciCakajoca piše events in orders;
-- vip-layout piše events + club_tables + table_holds. Reproducirana mrtva zanka 40P01 (nakup proti migraciji, ki je držala SHARE na events in čakala na orders) je bila razlog za razdelitev.


BEGIN;

CREATE INDEX IF NOT EXISTS events_vip_layout_from_club_idx        ON events (vip_layout_from_club_id)            WHERE vip_layout_from_club_id IS NOT NULL;

COMMIT;
