---
name: podatkovna-migracija
description: Postopek za migracije, ki spreminjajo ali brišejo produkcijske podatke (ponastavitev vrstic, izbris demo vsebine), in za številčenje migracij ob vzporednih PR-jih. Uporabi pred pisanjem ali mergeom vsake migracije, ki ni samo sprememba sheme.
---
# Podatkovna migracija: pasti, ki smo jih že plačali

Vir: `docs/UCENJE.md` (outly-hq), vrstice 21. 10., 23. 10. (e-računi, admin panel, #327), 24. 10. (066/067). Pravila 1–2 v `CLAUDE.md` veljajo naprej.

1. **Številka migracije.** Pred pisanjem preglej odprte PR-je drugih sej (`db/migracije/` v njihovih vejah): 054/055 (21. 10.), 057, 061/062 (23. 10.) so bile zasedene ali podvojene.
   Ob konfliktu prenumerira PR, ki je mergan kasneje; `migrate.js` manjkajoče uporabi po imenu, a številka mora ostati enolična.
2. **Evidenca.** Vsaka nova migracija gre v `db/VSE_MIGRACIJE.sql` (z odtisom) in v `db/schema.sql`. 067 je 24. 10. manjkala v evidenci — pregled jo je ujel; preveri sam.
3. **Ponastavitev vrstice za ponovitev** (npr. račun v ponovni poskus): nastavi `naslednji_poskus_at = NOW() + interval '5 minutes'`, ne `NOW()`. Ob deployu stara instanca še nekaj sekund teče in pograbi vrstico (061 → popravek 063/064).
4. **Test na dveh bazah.** Prazna baza IN baza s podatki; pri več migracijah v isti seji `node db/migrate.js --do NNN`, da testiraš vsako posebej. Vsak agent svojo bazo (`outly_<ime>`).
5. **Varovala brišoče migracije.** Pregled je 24. 10. ujel, da bi varovalo v 066 ustavilo deploy zaradi sandbox vračila; preveri, da varovalo ne zadene testnih/sandbox podatkov.
6. **Pred mergeom podatkovne migracije:** ročni zagon `Varnostna kopija baze` (workflow_dispatch). **Po njej** (namerno brisanje) takoj ročno `potrdi_padec = true`, sicer naslednji dnevni zagon javi lažni alarm `padec-stevil` (kopija #27, 24. 10.; glej `obnova-baze`).
7. Brišoča ali spreminjajoča migracija čaka Martinov DA in oznako `odobril-martin`; ne mergaj brez izrecnega DA v chatu (oznaka sama brez sporočila v seji ni dovolj, ker vsi pišejo kot isti uporabnik).
