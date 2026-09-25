-- 021_ogledi.sql
-- "Check activity" na nadzorni plosci kluba (Martin, 25. 9. 2026): kliki na profil kluba
-- in kliki na dogodke, po dnevih. Steje SAMO stevilo - brez IP-ja, brez uporabnika, brez
-- casovnega zigosanja posameznega klika (GDPR: ni osebnih podatkov, samo agregiran stevec).
--
-- event_id NULL = ogled profila kluba; event_id izpolnjen = ogled tega dogodka (club_id se
-- prepise iz dogodka, da je vrstica vedno pravilno uvrscena tudi, ce se dogodek pozneje
-- premakne med klubi - kar se sicer ne zgodi, a ostane brez dvoumnosti).
--
-- Nic od tega ne spreminja obstojecih podatkov: ena nova tabela.

BEGIN;

CREATE TABLE IF NOT EXISTS view_counts (
    club_id  INTEGER NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    event_id INTEGER REFERENCES events(id) ON DELETE CASCADE,
    day      DATE    NOT NULL,
    count    INTEGER NOT NULL DEFAULT 0
);

-- En zapis na (klub, dogodek-ali-profil, dan). COALESCE(event_id, 0) zdruzi vse
-- profilne oglede kluba na en dan v eno vrstico (event_id NULL sicer v UNIQUE ne bi zaznaval
-- podvojenih vrstic - NULL <> NULL).
CREATE UNIQUE INDEX IF NOT EXISTS view_counts_uniq
    ON view_counts (club_id, COALESCE(event_id, 0), day);

COMMIT;
