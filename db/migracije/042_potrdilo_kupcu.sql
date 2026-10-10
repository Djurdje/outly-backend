-- 042_potrdilo_kupcu.sql
-- POTRDILO O NAKUPU PO E-POSTI ZA KUPCA Z RACUNOM (issue #95; ZVPot-1 132/6: potrdilo o sklenitvi pogodbe na trajnem nosilcu).
-- Gost ga dobi ze od 033 (guest_mail_*); kupec z racunom ga ob placilu dobi zdaj. Stanje maila je v treh stolpcih po vzoru gosta (guest_mail_*), z drugim imenom,
-- ker sta poti locena: gostujoce narocilo (user_id NULL) ima mail z vstopnicami, narocilo kupca z racunom ima potrdilo brez kod QR (vstopnice so v aplikaciji).
--
-- receipt_mail_attempts  NULL = potrdilo NI dolgovano (stara narocila, gostujoca, guest lista, neplacana). 0..8 = dolgovano, stevilo ze porabljenih poskusov.
--                        Nastavi ga koda ob prehodu v `paid` (test nacin / brezplacno takoj, Stripe ob webhooku ali pospravljalcu).
--                        Obstojecih vrstic se NE dotikamo (brez UPDATE): po deployu nobeno staro narocilo ne dobi maila.
-- receipt_mail_claimed_at  cas zadnje rezervacije poskusa (UPDATE ... RETURNING, kot guest_mail_claimed_at); premor do naslednjega poskusa
--                        narasca (2 min .. 24 h), spodnja meja = rok Resenda + rezerva (#201).
-- receipt_mail_sent_at   cas uspesno poslanega maila (sele po uspehu Resenda): natanko enkrat OB USPEHU.
--
-- Samo DODAJANJE (trije nullable stolpci brez privzete vrednosti + delni indeks); obstojeci podatki in odgovori se ne spremenijo.

BEGIN;

ALTER TABLE orders ADD COLUMN IF NOT EXISTS receipt_mail_attempts SMALLINT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS receipt_mail_claimed_at TIMESTAMPTZ;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS receipt_mail_sent_at TIMESTAMPTZ;

-- Pospravljalec neposlanih potrdil: samo dolgovana in se neposlana.
CREATE INDEX IF NOT EXISTS orders_receipt_mail_idx ON orders (id) WHERE receipt_mail_attempts IS NOT NULL AND receipt_mail_sent_at IS NULL;

COMMENT ON COLUMN orders.receipt_mail_attempts IS 'Potrdilo po e-posti kupcu z racunom (042, #95): NULL = ni dolgovano; 0..8 = dolgovano, porabljeni poskusi. Nastavi koda ob prehodu v paid.';
COMMENT ON COLUMN orders.receipt_mail_claimed_at IS 'Cas zadnje rezervacije poskusa posiljanja potrdila (042). Premor do naslednjega poskusa narasca.';
COMMENT ON COLUMN orders.receipt_mail_sent_at IS 'Cas uspesno poslanega potrdila kupcu z racunom (042). Zapise se sele po uspehu Resenda.';

COMMIT;
