-- 030_stripe_checkout.sql
-- Stripe Checkout + Connect (issue #19): placilo prek Stripove gostovane strani namesto takojsnjega testnega "paid".
--
-- Samo DODAJANJE: trije nullable stolpci v orders, unikaten delni indeks in nova tabela stripe_events.
-- Obstojecih podatkov ne bere, ne spreminja in ne brise. Testna narocila (stripe_payment_intent_id LIKE 'test_%') ostanejo, kot so.
--
-- orders.stripe_checkout_session_id  cs_... seja, v kateri kupec placa; po njej webhook najde narocilo.
-- orders.checkout_url                 URL Stripove strani; ponovitev nakupa z istim Idempotency-Key vrne isti URL.
-- orders.checkout_expires_at          kdaj seja poteče; po tem pospravljalec narocilo preveri pri Stripu in ga preklice (sprosti zalogo).
-- stripe_events                       ze obdelani dogodki webhooka (evt_...): Stripe isti dogodek lahko poslje veckrat.
--
-- Zaklep in cas: ADD COLUMN brez privzete vrednosti je samo sprememba kataloga (ACCESS EXCLUSIVE za milisekunde).
-- CREATE INDEX brez CONCURRENTLY (ne gre v transakciji migrate.js) na indeksu, ki zajame samo nove vrstice (vse obstojece imajo NULL).
BEGIN;

ALTER TABLE orders ADD COLUMN IF NOT EXISTS stripe_checkout_session_id TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS checkout_url TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS checkout_expires_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS orders_checkout_session_key
    ON orders (stripe_checkout_session_id) WHERE stripe_checkout_session_id IS NOT NULL;

-- Pospravljalec isce samo cakajoca narocila; delni indeks ostane majhen.
CREATE INDEX IF NOT EXISTS orders_pending_idx
    ON orders (created_at) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS stripe_events (
    id          TEXT        PRIMARY KEY,
    type        TEXT        NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON COLUMN orders.stripe_checkout_session_id IS 'Stripe Checkout seja (cs_...), issue #19. NULL pri testnih narocilih.';
COMMENT ON COLUMN orders.checkout_url IS 'URL Stripove placilne strani za cakajoce narocilo (ponovitev z Idempotency-Key vrne istega).';
COMMENT ON COLUMN orders.checkout_expires_at IS 'Potek Checkout seje; pospravljalec po njem narocilo preveri pri Stripu in preklice.';
COMMENT ON TABLE stripe_events IS 'Ze obdelani Stripe webhook dogodki (idempotenca, issue #19).';

COMMIT;
