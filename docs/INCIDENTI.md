# Incidenti — kaj je že pokvarilo produkcijo

Dnevnik vsega, kar je v produkciji odpovedalo ali sprožilo alarm, vključno z lažnimi alarmi.
Ni za krivdo, ampak za **prepoznavanje vzorca**: ista napaka drugič mora biti ugotovljena v minutah, ne urah.

**Pravilo (velja za Popravljalca in vsako sejo, ki se dotakne produkcije):**

1. **Preberi to tabelo, preden postavljaš diagnozo.** Pogosto je odgovor že tu — in prihrani napačno smer.
2. **Dopiši vrstico ob koncu seje**, tudi če je bil alarm lažen ali si vzroka ne našel
   (»vzrok neznan« je uporaben podatek; tri take vrstice zapored so sum na resnično napako).

Ena vrstica = en incident. Najnovejši na dnu. Če je iz incidenta padla odločitev, gre ta v `DECISIONS.md`;
če je past, ki se lahko ponovi, gre v `CLAUDE.md` ali `STATE.md`. Tu ostane samo dogodek.

Polja:

- **datum** — ISO (2026-09-17), po potrebi z uro UTC.
- **kaj** — kaj je uporabnik ali alarm videl (simptom, ne vzrok).
- **vzrok** — zakaj se je to zgodilo. Če ni znan: »neznan«.
- **popravek** — kaj je stanje dejansko popravilo (PR, revert, nastavitev, nič).
- **trajanje** — od alarma do zelenega, približno.
- **seja** — povezava do seje Claude Code ali PR-ja, da je sled berljiva.

| datum | kaj | vzrok | popravek | trajanje | seja |
|---|---|---|---|---|---|
| 2026-09-17 | Nadzor produkcije rdeč, sprožil rutino Popravljalec | **Lažni alarm.** Namerni test celotne verige opozarjanja: na veji `test/nadzor-pravi-alarm` je bil spremenjen pričakovan status `/clubs`. Produkcija je bila ves čas zdrava (zadnji redni zagon na `main` ob 22:08 UTC zelen, mergeev v `main` ni bilo). | Nič — alarm je deloval, kot mora | ~0 (ni bilo okvare) | [PR #11](https://github.com/Djurdje/outly-backend/pull/11) |
| 2026-09-18 04:14–12:55 CEST | UptimeRobot monitor »Supabase Auth (prijava)« ves čas »Down« (401 Unauthorized), 8 h 40 min | **Lažni alarm.** Supabase `/auth/v1/health` brez glave `apikey` vrne 401; workflow `Nadzor produkcije` glavo pošilja in je isti trenutek dobil 200 (zagon 35298516604). UptimeRobot na brezplačnem paketu glav ne pošilja. Napaka pri nastavitvi monitorja (agent), ne Supabase. | Monitor pobrisan prek API-ja; Supabase Auth preverja naprej workflow (s pravo glavo). | ~8 h 40 min (brez okvare) | ta seja |
