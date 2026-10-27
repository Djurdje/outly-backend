-- 071_indeksi_tujih_kljucev_orders.sql
-- INDEKS ZA TUJI KLJUC ORDERS (issue #374): samo DODAJANJE indeksa, brez UPDATE/DELETE podatkov.
-- Del razdelitve 068–072 (issue #374, STATE.md past 3b, najdba pregleda PR #376): glej uvod v 068_indeksi_tujih_kljucev.sql (zakaj, popis tabel, ki se pisejo skupaj).
-- Ta migracija zaklene SAMO: orders.
--
-- Ločena: nakup (orders + sprožilec events + tickets), Stripe webhook (orders + tickets), prevzem gostujočih naročil (orders + tickets + ticket_transfers), guest lista (orders + guest_lists + tickets).


BEGIN;

CREATE INDEX IF NOT EXISTS orders_package_idx                     ON orders (package_id)                         WHERE package_id IS NOT NULL;

COMMIT;
