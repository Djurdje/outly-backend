## Kaj in zakaj

<!-- Ena do tri povedi: kaj se spremeni in kateri problem to resi. Brez implementacijskih podrobnosti. -->

## Preverjeno

<!-- Kateri testi so tekli, kaj je bilo preverjeno rocno, kaj NI bilo preverjeno. -->

## Kontrolni seznam

- [ ] **Testi so zeleni** — `npm test` lokalno in workflow `Testi` na tem PR-ju. Rdec PR se ne zdruzi.
- [ ] **`docs/STATE.md` je posodobljen** — ali pa v opisu pise, zakaj sprememba stanja ne premakne.
- [ ] **Vsaka Martinova korekcija med delom je zapisana** — ne samo popravljena:
      ponavljajoca past → `CLAUDE.md` ali `docs/STATE.md`; odlocitev, ki je padla → `docs/DECISIONS.md`
      (s polji *vir/dokaz*, *velja dokler*, *nadomescena z*).
- [ ] **Produkcija po deployu preverjena** — `GET /clubs` in `GET /events` → 200, `GET /me/invites` brez zetona → 401
      (~60–90 s po merge-u). Spletna stran: `https://outly.si` → 200. Ce pade, takoj popravek ali revert PR.
- [ ] **Hrosc brez regresijskega testa ni popravljen** — vsak popravek hrosca prinese test, ki pade na stari kodi.
      Preveri tako: test pozeni PRED popravkom (mora pasti) in po njem (mora biti zelen).
- [ ] **Nova invarianta ali mehanizem** → vrstica v `docs/ARCHITECTURE.md`, razdelek »Poslovne invariante« (z mehanizmom in testom).
- [ ] **Sprememba API-ja je samo dodajanje** — brisanje ali preimenovanje polja zahteva zapis v `docs/STATE.md`
      in obvestilo agentoma iOS in spletne strani (v opisu tega PR-ja).
- [ ] **Migracija**: nova ostevilcena datoteka, dopisana v `db/VSE_MIGRACIJE.sql`, osvezen `db/schema.sql`,
      preverjena na prazni bazi IN na bazi s podatki. Ce brise ali spreminja produkcijske podatke → **caka Martinov DA**.
- [ ] **Brez poverilnic v diffu** — ne gesel, ne kljucev, ne `DATABASE_URL`, ne zetonov.

## Kaj naj preveri Martin

<!-- Kar agent sam ne more: naprava, denar, nastavitve racunov, pravno. Ce ni nicesar, napisi "nic". -->

## Oznaka `odobril-martin`

<!-- Workflow "Zascita" zahteva to oznako, ce PR spreminja .github/workflows/**, CLAUDE.md, .claude/**,
     db/migracije/** ali placilno/dostopno logiko (requireRole/requireClub, orders, tickets, stripe).
     Oznako doda Martin — agent si je ne sme dodati sam. -->
