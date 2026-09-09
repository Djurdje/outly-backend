-- 008_prenos_vstopnic.sql
-- Prenos vstopnice prijatelju: kupec kupi 4, vsak dobi svojo.
--
-- Zakaj: brez tega so vse vstopnice naročila na kupcu in na vratih morajo
-- vsi priti skupaj. Prenos ne spreminja naročila (denar, račun ostaneta na
-- kupcu) — spremeni samo IMETNIKA vstopnice in izda nov QR.
--
-- Pravila (uveljavlja index.js, POST /tickets/:id/transfer):
--   – prenese lahko samo trenutni imetnik (kupec ali kdor jo je prejel),
--   – samo veljavna vstopnica ('valid') in samo pred začetkom dogodka,
--   – prejemnik mora imeti Outly račun (po e-naslovu) in izpolnjevati min_age,
--   – ob prenosu se serial zamenja -> star QR ne velja več (skener: "unknown").
--
-- holder_user_id = NULL pomeni, da je imetnik kupec (orders.user_id).
-- Če imetnik izbriše račun (ON DELETE SET NULL), se vstopnica vrne kupcu —
-- vstopnica je plačana in ne sme izginiti.
BEGIN;

ALTER TABLE tickets
  ADD COLUMN IF NOT EXISTS holder_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS tickets_holder_idx
  ON tickets (holder_user_id) WHERE holder_user_id IS NOT NULL;

-- Sledljivost: kdo je komu kdaj prenesel; stara in nova koda.
CREATE TABLE IF NOT EXISTS ticket_transfers (
    id            BIGSERIAL   PRIMARY KEY,
    ticket_id     BIGINT      NOT NULL REFERENCES tickets(id) ON DELETE RESTRICT,
    from_user_id  INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    to_user_id    INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    to_email      TEXT        NOT NULL,
    old_serial    UUID        NOT NULL,
    new_serial    UUID        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ticket_transfers_ticket_idx ON ticket_transfers (ticket_id, created_at DESC);

COMMIT;
