-- 018_vec_klubov_na_osebo.sql
-- Ena oseba je lahko v ekipi VEC klubov (Luka, 21. 9. 2026): vratar ali manager, ki dela v K4,
-- dobi in sprejme vabilo tudi iz Cirkusa. Do zdaj je bila omejitev UNIQUE (user_id) iz 009
-- ("en klub, da je 'moj klub' enolicen"). Zdaj je enolicen par (club_id, user_id); kateri klub
-- zeli aplikacija, pove z glavo X-Outly-Club (ali ?club_id=) — brez nje backend vzame prvo
-- clanstvo, kot doslej (star odjemalec dela naprej).
-- Lastnik kluba se vedno ne more biti clan druge ekipe (preverja index.js).
BEGIN;

ALTER TABLE club_members DROP CONSTRAINT IF EXISTS club_members_user_id_key;

CREATE UNIQUE INDEX IF NOT EXISTS club_members_club_user_uniq ON club_members (club_id, user_id);
CREATE INDEX IF NOT EXISTS club_members_user_idx ON club_members (user_id, created_at);

COMMIT;
