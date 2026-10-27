-- 072_indeksi_tujih_kljucev_tickets.sql
-- INDEKS ZA TUJI KLJUC TICKETS (issue #374): samo DODAJANJE indeksa, brez UPDATE/DELETE podatkov.
-- Del razdelitve 068–072 (issue #374, STATE.md past 3b, najdba pregleda PR #376): glej uvod v 068_indeksi_tujih_kljucev.sql (zakaj, popis tabel, ki se pisejo skupaj).
-- Ta migracija zaklene SAMO: tickets.
--
-- Ločena: sken (tickets + table_service v enem stavku), nakup (orders + events + tickets), prenos (tickets + ticket_transfers), guest lista (tickets + guest_list_members + guest_lists).
-- Pisalni strosek: delni indeks na used_by_user_id; sken vstopnice (UPDATE status/used_at/used_by_user_id) ze zdaj ni HOT (status je v tickets_event_idx), zato je nov vnos v delni indeks
-- na skenirano vstopnico en dodaten list B-drevesa (izmerjeno lokalno ~+5 us na vrstico). Ker je tickets na poti skena, je ta migracija zadnja in zaklepa samo to tabelo.


BEGIN;

CREATE INDEX IF NOT EXISTS tickets_used_by_idx                    ON tickets (used_by_user_id)                   WHERE used_by_user_id IS NOT NULL;

COMMIT;
