-- 055_pavza_prodaje_admin_dejanja.sql
-- PAVZA PRODAJE IN DNEVNIK ADMIN DEJANJ (admin panel faza 1, Martin 21. 10. 2026): samo DODAJANJE stolpca, tabele in indeksov, brez UPDATE/DELETE obstojecih vrstic.
--
-- events.sales_paused   Stikalo »Prodaja tece / ustavljena«. TRUE = nakup vstopnic, VIP miz in nakup gosta vrne 409 »Ticket sales are paused.« (napakaProdaje v index.js),
--                       cena in okno prodaje ostaneta (prej je bila edina pot brisanje cene, ki ceno izgubi in VIP miz ne ustavi). Ob vklopu se odprta Stripe
--                       placilna okna dogodka zaprejo v ozadju (pavza_prodaje.js, invarianta I53). Privzeto FALSE: obstojeci dogodki se ne spremenijo.
--
-- admin_dejanja         Ena vrstica na spremembo, ki jo naredi vloga admin (panel ali isti API): kdo, kdaj, kaj, prej/potem (samo spremenjena polja).
--                       Vpise jo ISTA transakcija kot spremembo (ce sprememba pade, vrstice ni; ce vpis pade, spremembe ni). Brez osebnih podatkov kupcev
--                       (e-naslovov, imen, Stripovih ID-jev): cilj je dogodek, ne naroceno. BIGSERIAL id pride v Node kot niz (setTypeParser(20) ga ze resi).
--   admin_user_id       id admina (users.id) BREZ tujega kljuca: CREATE TABLE ... REFERENCES users bi vzel SHARE ROW EXCLUSIVE na `users` do COMMIT-a
--                       in ga drzal tudi med cakanjem na zaklep `events` spodaj (prijava/GET /me pise v users). Ob izbrisu admina id ostane (ni osebni podatek
--                       kupca); panel e-naslov admina prebere z LEFT JOIN users (izbrisan = »izbrisan admin«).
--   dejanje             npr. event.update, event.publish, event.unpublish, event.cancel, event.sales_pause, event.sales_resume.
--   cilj_tip, cilj_id   npr. ('event', '35'); TEXT, da kasneje sprejme tudi druge cilje (order, user, club) brez migracije.
--   prej, potem         JSONB objekta {polje: vrednost} samo s spremenjenimi polji.
--
-- Zaklep: nova tabela nima tujih kljucev, zato ne zaklepa nobene obstojece tabele. ADD COLUMN z nespremenljivo privzeto vrednostjo je v PostgreSQL 16 samo
-- sprememba kataloga (brez prepisa tabele), a vzame kratek ACCESS EXCLUSIVE na `events`. Sken (skenPool, lock_timeout 1 s) ob tem vrne 503 + Retry-After in telefon preklopi na sken brez povezave (I16). migrate.js nastavi lock_timeout in
-- migracijo ob izteku ponovi. Deploy ne med dogodkom.

BEGIN;

CREATE TABLE IF NOT EXISTS admin_dejanja (
    id             BIGSERIAL   PRIMARY KEY,
    cas            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    admin_user_id  INTEGER,
    dejanje        TEXT        NOT NULL CHECK (char_length(dejanje) BETWEEN 1 AND 60),
    cilj_tip       TEXT        NOT NULL CHECK (char_length(cilj_tip) BETWEEN 1 AND 30),
    cilj_id        TEXT        NOT NULL CHECK (char_length(cilj_id) BETWEEN 1 AND 60),
    prej           JSONB,
    potem          JSONB,
    razlog         TEXT        CHECK (razlog IS NULL OR char_length(razlog) <= 500)
);

CREATE INDEX IF NOT EXISTS admin_dejanja_cilj_idx ON admin_dejanja (cilj_tip, cilj_id, cas DESC);
CREATE INDEX IF NOT EXISTS admin_dejanja_cas_idx ON admin_dejanja (cas DESC);

COMMENT ON TABLE admin_dejanja IS 'Dnevnik admin dejanj (055, admin panel faza 1): kdo, kdaj, kaj, prej/potem; vpis v isti transakciji kot sprememba. Brez osebnih podatkov kupcev.';

-- Pospravljalec (placila_stripe.js preveriPreklicane, I53): preklicana narocila s sejo brez placila, zadnjih 40 min. Delni indeks je majhen; gradnja vzame kratek
-- SHARE na `orders` (nakupi pocakajo za cas gradnje, pri danasnji velikosti manj kot sekunda).
CREATE INDEX IF NOT EXISTS orders_preklic_seja_idx ON orders (cancelled_at)
    WHERE status = 'cancelled' AND stripe_checkout_session_id IS NOT NULL AND stripe_payment_intent_id IS NULL;

-- Stolpec na `events` ZADNJI: ACCESS EXCLUSIVE na events se drzi do COMMIT, zato pred njim ni nicesar, kar bi cakalo.
ALTER TABLE events ADD COLUMN IF NOT EXISTS sales_paused BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN events.sales_paused IS 'Pavza prodaje (055): TRUE = nakup vstopnic, miz in gosta 409 »Ticket sales are paused.«, cena ostane; odprta placilna okna se zaprejo (I53).';

COMMIT;
