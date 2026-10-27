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
-- (Indeksa na `orders` in `tickets` sta zdaj v 071 in 072, glej spodaj.)
--
-- RAZDELITEV V MIGRACIJE 068–072 (STATE.md past 3b »migracija naj ne zaklepa dveh vrocih tabel«; najdba pregleda PR #376):
-- CREATE INDEX (ne CONCURRENTLY: migrate.js vsako migracijo zavije v transakcijo, CONCURRENTLY v transakciji ni dovoljen) vzame SHARE zaklep na tabeli do COMMIT.
-- SHARE se ne ujema z ROW EXCLUSIVE (INSERT/UPDATE/DELETE), zato aplikacija pisanja v tabelo cakajo, bralci (tudi sken, ki bere) ne. Ce migracija v ENI transakciji
-- zaklene tabeli A in B, aplikacija pa v svoji transakciji pise obe v nasprotnem vrstnem redu, nastane mrtva zanka (40P01): migracija drzi SHARE na A in caka na B,
-- aplikacija drzi ROW EXCLUSIVE na B in caka na A. Reproducirano lokalno: nakup `INSERT INTO orders` -> sprozilec `rezerviraj_zalogo` `UPDATE events` proti migraciji,
-- ki je (stara 068) zaklenila events in nato orders: nakup `40P01` -> 503 NAKUP_ZASEDEN. Zato NOBENA migracija ne zaklene dveh tabel, ki ju katerakoli
-- transakcija aplikacije (ali sprozilec, ali en sam stavek s CTE) pise skupaj. Tabele s tem popisom so zbrane v _testi/test_indeksi_fk.js (SKUPAJ_PISANE); test pade,
-- ce se kateri par znajde v isti migraciji.
--
--   Pisano skupaj (pot -> tabele):
--     nakup vstopnic POST /events/:id/orders, gostov nakup, Stripe webhook (zakljuci)  orders + events (sprozilec rezerviraj_zalogo/sprosti_zalogo) + tickets
--     VIP nakup mize (placanoTakoj), guest lista (guestListaVhod)                       orders + tickets (+ guest_lists)
--     sken POST /business/tickets/scan, scan-batch (stavek s CTE STREZBA_CTE)          tickets + table_service
--     prenos vstopnice POST /tickets/:id/transfer, cistilci gostovih e-naslovov         tickets + ticket_transfers
--     prevzem gostujocih narocil ob prijavi (en stavek s CTE)                           orders + tickets + ticket_transfers
--     guest lista: povabila, odstranitev, preklic, izbris racuna gostitelja              tickets + guest_list_members + guest_lists
--     pavza prodaje / odpoved (prekliciCakajoca) in PATCH /events/:id                   orders + events
--     VIP razpored dogodka PUT /business/events/:id/vip-layout                          club_tables + table_holds + events
--     VIP razpored kluba PUT /business/vip                                              club_tables + bottle_packages
--     sprejem povabila v ekipo POST /me/invites/:id/accept                              club_members + club_invites
--   Brez para (nikoli v isti transakciji z drugo tabelo s tega popisa): creator_applications, reports, friend_requests, view_counts, club_event_notifications.
--   IZJEMA, ki je razdelitev ne more razresiti: kaskadni DELETE (DELETE /me, brisanje dogodka/kluba I63, admin_brisanje.js) pise posredno skoraj vse otroske tabele
--   v eni transakciji. Te poti so redke, niso na poti nakupa ali skena (DELETE /me je omejen na 5 na uro, brisanje je admin dejanje), migracija pa je v 0,3 s;
--   ob mrtvi zanki lahko pade ena od obeh strani: klicatelj dobi napako (DELETE /me vrne 500, uporabnik ponovi), migrate.js pa migracijo ponovi (40P01 in 55P03).
--
--   Razporeditev (nobena migracija ne vsebuje dveh tabel iz istega reda zgoraj):
--     068 (ta datoteka)  creator_applications, reports, club_members, friend_requests, view_counts, club_event_notifications, club_tables, guest_lists, ticket_transfers, table_service
--     069                club_invites, bottle_packages, table_holds, guest_list_members  (pari tabel iz 068: club_members, club_tables, guest_lists)
--     070 events   071 orders   072 tickets  (vsaka sama: nakup pise vse tri, sken tickets + table_service). Vroci tabeli sta ZADNJI: njun SHARE zaklep traja en sam stavek.
--   PR z migracijami 068–072 NE v dogodek in ne manj kot 3 h pred njim (merge = deploy z migracijami).

BEGIN;
-- Sken (skenPool) ima lock_timeout 1 s: migracija ne caka na zaklep dlje kot 800 ms, da sken pred njo ne obtici v vrsti
-- in ne pade (pregled PR #376, 2. krog N1); migrate.js ob izteku (55P03) migracijo ponovi.
SET LOCAL lock_timeout = '800ms';

CREATE INDEX IF NOT EXISTS creator_applications_user_idx          ON creator_applications (user_id)              WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS creator_applications_club_idx          ON creator_applications (club_id)              WHERE club_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS creator_applications_decided_by_idx    ON creator_applications (decided_by)           WHERE decided_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS reports_resolved_by_idx                ON reports (resolved_by)                       WHERE resolved_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS club_members_invited_by_idx            ON club_members (invited_by_user_id)           WHERE invited_by_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS friend_requests_from_user_idx          ON friend_requests (from_user_id);
CREATE INDEX IF NOT EXISTS friend_requests_to_user_idx            ON friend_requests (to_user_id);
CREATE INDEX IF NOT EXISTS club_event_notifications_event_idx     ON club_event_notifications (event_id);
CREATE INDEX IF NOT EXISTS view_counts_event_idx                  ON view_counts (event_id)                      WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS club_tables_club_all_idx               ON club_tables (club_id);
CREATE INDEX IF NOT EXISTS guest_lists_created_by_idx             ON guest_lists (created_by)                    WHERE created_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS guest_lists_host_user_idx              ON guest_lists (host_user_id)                  WHERE host_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ticket_transfers_from_user_idx         ON ticket_transfers (from_user_id)             WHERE from_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ticket_transfers_to_user_idx           ON ticket_transfers (to_user_id)               WHERE to_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS table_service_event_idx                ON table_service (event_id);
CREATE INDEX IF NOT EXISTS table_service_delivered_by_idx         ON table_service (delivered_by_user_id)        WHERE delivered_by_user_id IS NOT NULL;

COMMIT;
