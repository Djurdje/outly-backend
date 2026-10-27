-- 069_indeksi_tujih_kljucev_2.sql
-- INDEKSI ZA TUJE KLJUCE, 2. del (issue #374): samo DODAJANJE indeksov, brez UPDATE/DELETE podatkov.
-- Del razdelitve 068–072 (issue #374, STATE.md past 3b, najdba pregleda PR #376): glej uvod v 068_indeksi_tujih_kljucev.sql (zakaj, popis tabel, ki se pisejo skupaj).
-- Ta migracija zaklene SAMO: club_invites, bottle_packages, table_holds, guest_list_members.
--
-- Ločena od 068, ker se vsaka od teh tabel piše skupaj s tabelo iz 068: club_invites + club_members (sprejem povabila v ekipo), bottle_packages + club_tables (PUT /business/vip),
-- table_holds + club_tables (+ events) (vip-layout), guest_list_members + guest_lists (+ tickets) (guest lista). Med seboj se tabele v 069 ne pišejo skupaj.


BEGIN;

CREATE INDEX IF NOT EXISTS club_invites_club_idx                  ON club_invites (club_id);
CREATE INDEX IF NOT EXISTS club_invites_user_idx                  ON club_invites (user_id);
CREATE INDEX IF NOT EXISTS club_invites_invited_by_idx            ON club_invites (invited_by_user_id)           WHERE invited_by_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS bottle_packages_club_all_idx           ON bottle_packages (club_id);
CREATE INDEX IF NOT EXISTS table_holds_created_by_idx             ON table_holds (created_by_user_id)            WHERE created_by_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS guest_list_members_guest_list_idx      ON guest_list_members (guest_list_id);
CREATE INDEX IF NOT EXISTS guest_list_members_user_all_idx        ON guest_list_members (user_id)                WHERE user_id IS NOT NULL;

COMMIT;
