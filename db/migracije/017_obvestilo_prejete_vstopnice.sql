-- 017_obvestilo_prejete_vstopnice.sql
-- Obvestilo "prijatelj ti je poslal vstopnico" v meniju obvestil (Martin, 21. 9. 2026).
--
-- ticket_transfers ze belezi vsak prenos (008); manjka samo, ali je prejemnik obvestilo
-- ze videl. seen_at NULL = neprebrano -> pokaze se v zvoncu (GET /me pending_received_tickets,
-- GET /me/tickets/received); POST /me/tickets/received/:id/seen ga nastavi.
--
-- Obstojeci prenosi (pred to migracijo) se stejejo za prebrane: stolpec se doda z DEFAULT NOW(),
-- ki napolni stare vrstice, nato se DEFAULT odstrani, da novi prenosi nastanejo z NULL.
-- Sicer bi vsak, ki je kdaj prejel vstopnico, po deployu dobil star "nov" zvonec.
BEGIN;

ALTER TABLE ticket_transfers
    ADD COLUMN IF NOT EXISTS seen_at TIMESTAMPTZ DEFAULT NOW();

ALTER TABLE ticket_transfers
    ALTER COLUMN seen_at DROP DEFAULT;

-- Obvestila: "moje neprebrane prejete vstopnice".
CREATE INDEX IF NOT EXISTS ticket_transfers_to_unseen_idx
    ON ticket_transfers (to_user_id) WHERE seen_at IS NULL;

COMMIT;
