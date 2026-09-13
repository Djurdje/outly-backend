-- 013_vabila_v_ekipo.sql
-- Vabila v ekipo kluba (Figma "My clubs" / "My clubs inv" / "My clubs con").
--
-- Zakaj: do zdaj je lastnik sodelavca dodal NEPOSREDNO (POST /business/team ->
-- vrstica v club_members brez privolitve). Po Figmi uporabnik vabilo prejme v
-- obvestilih ("X has sent you an invitation to work as a Manager") in ga sprejme
-- ali zavrne. Šele ob sprejemu nastane vrstica v club_members.
--
-- Stanja: pending -> accepted | declined | cancelled (lastnik/manager prekliče).
-- Uporabnik ima za isti klub največ ENO čakajoče vabilo (delni unikatni indeks);
-- lahko pa ima čakajoča vabila več klubov — ob sprejemu enega se ostala
-- označijo kot declined (uporabnik je lahko v največ eni ekipi, migracija 009).
-- Vabilo velja samo za uporabnika, ki že ima Outly račun (kot prej).
BEGIN;

CREATE TABLE IF NOT EXISTS club_invites (
    id                  SERIAL      PRIMARY KEY,
    club_id             INTEGER     NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    user_id             INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role                TEXT        NOT NULL CHECK (role IN ('manager', 'doorman')),
    status              TEXT        NOT NULL DEFAULT 'pending'
                                    CHECK (status IN ('pending', 'accepted', 'declined', 'cancelled')),
    invited_by_user_id  INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    responded_at        TIMESTAMPTZ
);

-- Največ eno čakajoče vabilo na (klub, uporabnik).
CREATE UNIQUE INDEX IF NOT EXISTS club_invites_pending_uniq
    ON club_invites (club_id, user_id) WHERE status = 'pending';

-- Obvestila uporabnika: "moja čakajoča vabila".
CREATE INDEX IF NOT EXISTS club_invites_user_pending_idx
    ON club_invites (user_id) WHERE status = 'pending';

COMMIT;
