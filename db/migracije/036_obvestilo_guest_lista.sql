-- 036_obvestilo_guest_lista.sql
-- Obvestilo "prijatelj te je dodal na svojo guest listo" v meniju obvestil / zvoncu (Martin, 8. 10. 2026: "dodaj obvestilo prijatelju ob vabilu").
-- Push obvestil projekt nima; obvestilo je obstojeci zvonec, isti vzorec kot 017 (ticket_transfers.seen_at, "X ti je poslal vstopnico").
--
-- guest_list_members (035) ze belezi vsako vabilo; manjka samo, ali je povabljenec obvestilo ze videl. seen_at NULL = neprebrano -> pokaze se v zvoncu
-- (GET /me pending_guest_list_invites, GET /me/guest-list-invites/received); POST /me/guest-list-invites/received/:id/seen ga nastavi.
-- Obvestilo izgine samo, ko je povabljenec odstranjen (removed_at), lista preklicana, vstopnica void ali dogodek koncan (pogoji v poizvedbi, ne v podatkih).
--
-- Obstojeca vabila (pred to migracijo) se stejejo za prebrana: stolpec se doda z DEFAULT NOW() (NOW() je stabilen, PG11+ ne prepisuje tabele),
-- ki napolni stare vrstice, nato se DEFAULT odstrani, da nova vabila nastanejo z NULL (kot 017).
-- Samo DODAJANJE (obstojecih podatkov ne spreminja).
BEGIN;

ALTER TABLE guest_list_members
    ADD COLUMN IF NOT EXISTS seen_at TIMESTAMPTZ DEFAULT NOW();

ALTER TABLE guest_list_members
    ALTER COLUMN seen_at DROP DEFAULT;

-- Obvestila: "moja neprebrana, se aktivna vabila" (GET /me steje ob vsakem zagonu aplikacije).
CREATE INDEX IF NOT EXISTS guest_list_members_neprebrana_idx
    ON guest_list_members (user_id) WHERE seen_at IS NULL AND removed_at IS NULL;

COMMENT ON COLUMN guest_list_members.seen_at IS 'Povabljenec je obvestilo o vabilu videl (zvonec). NULL = neprebrano; vabila pred 036 so prebrana.';

COMMIT;
