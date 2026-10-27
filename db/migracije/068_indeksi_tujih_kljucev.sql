-- 068_indeksi_tujih_kljucev.sql
-- INDEKSI ZA TUJE KLJUCE BREZ INDEKSA (issue #374 tocka 1): samo DODAJANJE indeksov, brez UPDATE/DELETE podatkov in brez spremembe stolpcev.
--
-- Zakaj: PostgreSQL ne naredi indeksa za tuji kljuc sam. Ko se izbrise vrstica v starsevski tabeli (brisanje dogodka/kluba I63, DELETE /me, pospravljalci),
-- mora za VSAK tuj kljuc, ki kaze nanjo, pregledati otroka po tem stolpcu: brez indeksa je to zaporedno branje cele otroske tabele (ON DELETE CASCADE / SET NULL
-- / RESTRICT). Isto velja za poizvedbe in stike po tem stolpcu (npr. table_service po event_id: obstojeci indeks (club_id, event_id, delivered_at) ima event_id
-- drugi, zato ne pomaga). Prej: 26 od 81 tujih kljucev brez uporabnega indeksa (preverba v _testi/test_indeksi_fk.js, invarianta I65).
--
-- Kateri: tuj kljuc je »pokrit«, ce ima veljaven indeks, ki se zacne z njegovimi stolpci, in je ali navaden ali delni z `WHERE stolpec IS NOT NULL`
-- (poizvedba kontrole kljuca `WHERE stolpec = $1` ta pogoj implicira, zato planer tak indeks uporabi). Delni indeksi z DRUGIM pogojem
-- (status = 'pending', archived_at IS NULL, revoked_at IS NULL, removed_at IS NULL, seen_at IS NULL, allow_guest) kontrole kljuca NE pokrijejo — zato jih
-- ta migracija dopolni z lastnim indeksom (club_invites, friend_requests.to_user_id, club_tables.club_id, bottle_packages.club_id, guest_lists.host_user_id,
-- guest_list_members, ticket_transfers).
--
-- Oblika: stolpec NOT NULL -> navaden indeks; stolpec, ki lahko je NULL (»kdo je naredil«, nepovezano) -> delni `WHERE stolpec IS NOT NULL` (manjsi indeks,
-- vzdrzevanje ob vpisu vrstice brez vrednosti je nic; isti vzorec kot events_venue_club_idx, orders_table_idx, tickets_holder_idx).
--
-- IZJEME: nobene. Vsi starsi (users, clubs, events, bottle_packages, guest_lists) so tabele s tisoci vrstic ali vec, nobena otroska tabela ni sifrant z desetimi
-- vrsticami. Izjeme za prihodnost so izrecno naštete v _testi/test_indeksi_fk.js (zdaj prazen seznam).
--
-- Pisalni strosek: indeksi na `tickets` (used_by_user_id, delni) in `orders` (package_id, delni): sken vstopnice (UPDATE status/used_at/used_by_user_id) ze zdaj ni
-- HOT (status je v tickets_event_idx), zato je nov vnos v delni indeks na skenirano vstopnico en dodaten list B-drevesa; nakup brez paketa (package_id NULL) indeksa
-- ne spremeni. Izmerjeno lokalno: UPDATE 20 000 vstopnic ~+5 us na vrstico z indeksom (sum meritve je vecji od razlike). Delni indeksi so zato edina izbira za nullable stolpce na vroci poti.
--
-- Zaklep: CREATE INDEX (ne CONCURRENTLY: migrate.js vsako migracijo zavije v transakcijo, CONCURRENTLY v transakciji ni dovoljen) vzame SHARE zaklep na otroski
-- tabeli do COMMIT: bralci (tudi sken, ki bere) niso ovirani, pisanja (nakup, sken UPDATE) cakajo, dokler se indeks gradi (cela migracija 0,3 s lokalno pri 200 tisoc vstopnicah in
-- 100 tisoc vrsticah table_service/orders). migrate.js nastavi lock_timeout (2 s) in migracijo ob izteku ponovi; stavki so zato razvrsceni tako, da so VROCE
-- tabele (orders, tickets) zadnje — njihov zaklep se drzi najkrajsi cas do COMMIT. PR z to migracijo NE v dogodek in ne manj kot 3 h pred njim.

BEGIN;

-- Majhne tabele (admin, prijave, vabila, porocila)
CREATE INDEX IF NOT EXISTS creator_applications_user_idx          ON creator_applications (user_id)              WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS creator_applications_club_idx          ON creator_applications (club_id)              WHERE club_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS creator_applications_decided_by_idx    ON creator_applications (decided_by)           WHERE decided_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS reports_resolved_by_idx                ON reports (resolved_by)                       WHERE resolved_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS club_members_invited_by_idx            ON club_members (invited_by_user_id)           WHERE invited_by_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS club_invites_club_idx                  ON club_invites (club_id);
CREATE INDEX IF NOT EXISTS club_invites_user_idx                  ON club_invites (user_id);
CREATE INDEX IF NOT EXISTS club_invites_invited_by_idx            ON club_invites (invited_by_user_id)           WHERE invited_by_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS friend_requests_from_user_idx          ON friend_requests (from_user_id);
CREATE INDEX IF NOT EXISTS friend_requests_to_user_idx            ON friend_requests (to_user_id);

-- Dogodek / klub: brisanje (I63) in izpisi po dogodku
CREATE INDEX IF NOT EXISTS events_vip_layout_from_club_idx        ON events (vip_layout_from_club_id)            WHERE vip_layout_from_club_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS club_event_notifications_event_idx     ON club_event_notifications (event_id);
CREATE INDEX IF NOT EXISTS view_counts_event_idx                  ON view_counts (event_id)                      WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS club_tables_club_all_idx               ON club_tables (club_id);
CREATE INDEX IF NOT EXISTS bottle_packages_club_all_idx           ON bottle_packages (club_id);
CREATE INDEX IF NOT EXISTS table_holds_created_by_idx             ON table_holds (created_by_user_id)            WHERE created_by_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS guest_lists_created_by_idx             ON guest_lists (created_by)                    WHERE created_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS guest_lists_host_user_idx              ON guest_lists (host_user_id)                  WHERE host_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS guest_list_members_guest_list_idx      ON guest_list_members (guest_list_id);
CREATE INDEX IF NOT EXISTS guest_list_members_user_all_idx        ON guest_list_members (user_id)                WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ticket_transfers_from_user_idx         ON ticket_transfers (from_user_id)             WHERE from_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ticket_transfers_to_user_idx           ON ticket_transfers (to_user_id)               WHERE to_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS table_service_event_idx                ON table_service (event_id);
CREATE INDEX IF NOT EXISTS table_service_delivered_by_idx         ON table_service (delivered_by_user_id)        WHERE delivered_by_user_id IS NOT NULL;

-- Vroci tabeli ZADNJI (zaklep se drzi do COMMIT): sken vstopnice in nakup
CREATE INDEX IF NOT EXISTS orders_package_idx                     ON orders (package_id)                         WHERE package_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS tickets_used_by_idx                    ON tickets (used_by_user_id)                   WHERE used_by_user_id IS NOT NULL;

COMMIT;
