-- 032_rezervacija_po_telefonu.sql
-- Rezervacija VIP mize po telefonu (Martin, 4. 10. 2026, pogovor v seji menedzerja: "rezervacija po telefonu kot plus").
-- Ce gost klub poklice in rezervira mizo, jo klub sam oznaci kot zasedeno na dogodku, da je prek Outly nihce ne more kupiti.
-- Placilo gre mimo Outly (gost placa v klubu), zato rezervacija NI narocilo: ne steje v prodajo, nima vstopnic, nima Stripa.
--
--   * table_holds   ena vrstica = ena miza na enem dogodku, ki jo je klub oznacil kot zasedeno.
--                   guest_name (1-60 znakov) in note (0-200) sta SAMO za osebje kluba; kupec ju nikoli ne vidi.
--                   Gost ni uporabnik Outly (ime je prosto besedilo), zato se vrstice brisejo po koncu dogodka
--                   (pospravljalec v index.js: konec dogodka + 24 h, brez end_at: start_at + 12 h + 24 h).
--   * UNIQUE (event_id, table_id)  ista miza se na istem dogodku ne rezervira dvakrat.
--
-- Invarianta I13 (miza se ne proda dvakrat) ni vec samo unikaten indeks na orders: unikatnega indeksa cez dve tabeli
-- ni, zato nakup (FOR SHARE) in rezervacija (FOR NO KEY UPDATE) zaklepata ISTO vrstico club_tables in nato vsak v
-- novem stavku preveri drugo tabelo (glej docs/ARCHITECTURE.md, I13).
--
-- Samo DODAJANJE: ena nova tabela in en indeks. Obstojecih podatkov ne bere in ne spreminja.
BEGIN;

CREATE TABLE IF NOT EXISTS table_holds (
    id                  SERIAL PRIMARY KEY,
    event_id            INTEGER     NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    table_id            INTEGER     NOT NULL REFERENCES club_tables(id) ON DELETE CASCADE,
    guest_name          TEXT        NOT NULL,
    note                TEXT,
    created_by_user_id  INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT table_holds_event_table_key UNIQUE (event_id, table_id),
    CONSTRAINT table_holds_guest_chk CHECK (char_length(btrim(guest_name)) BETWEEN 1 AND 60),
    CONSTRAINT table_holds_note_chk  CHECK (note IS NULL OR char_length(note) <= 200)
);

-- UNIQUE (event_id, table_id) ze pokriva iskanje po dogodku; ta indeks je za tuji kljuc proti club_tables.
CREATE INDEX IF NOT EXISTS table_holds_table_idx ON table_holds (table_id);

COMMENT ON TABLE table_holds IS 'Rezervacija mize po telefonu (klub jo oznaci sam; ni narocilo, ni prodaja). Osebni podatek: guest_name/note, brise se po koncu dogodka.';
COMMENT ON COLUMN table_holds.guest_name IS 'Ime gosta, ki je poklical klub (prosto besedilo, ne uporabnik Outly). Samo za osebje kluba.';

COMMIT;
