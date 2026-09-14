-- 014_cenik_bara.sql
-- Cenik bara kluba (gumb "Bar prices" na zaslonu dogodka, Martin 14. 9. 2026).
--
-- Zakaj JSONB in ne lastna tabela: cenik je kratek seznam (pivo, vino, koktajli ...),
-- ki ga klub ureja v celoti naenkrat in ga aplikacija bere v celoti naenkrat.
-- Ni iskanja po postavkah, ni tujih kljucev, ni statistike. Ena vrstica na klub.
--
-- Oblika: [{ "name": "Pivo 0,5 l", "price_cents": 400, "category": "Beer" }, ...]
-- price_cents = celo stevilo centov (nikoli plavajoca vejica; kot pri vstopnicah).
-- category je neobvezna (aplikacija postavke zdruzi po kategoriji).
-- Vrstni red v seznamu = vrstni red prikaza. Najvec 60 postavk (preverja backend).
BEGIN;

ALTER TABLE clubs
    ADD COLUMN IF NOT EXISTS bar_prices JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Samo seznam; objekt ali skalar bi aplikaciji podrl dekodiranje celotnega kluba.
ALTER TABLE clubs DROP CONSTRAINT IF EXISTS clubs_bar_prices_chk;
ALTER TABLE clubs
    ADD CONSTRAINT clubs_bar_prices_chk CHECK (jsonb_typeof(bar_prices) = 'array');

COMMIT;
