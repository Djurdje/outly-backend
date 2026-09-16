# Outly backend — navodila za agente

Express + PostgreSQL 16 na Renderju. Streže iOS aplikacijo Outly in admin panel.
Odgovarjaj v slovenščini, kratko in naravnost. Martin (lastnik) ni razvijalec po
poklicu: razlagaj posledice, ne implementacijskih podrobnosti. Če se moti, povej.

Skupni možgani projekta (preberi, preden karkoli spremeniš):
- `docs/DECISIONS.md` — odločitve, ki so padle. Ne odpiraj jih znova.
- `docs/STATE.md` — trenutno stanje, odprte naloge, znane blokade. **Ob koncu vsakega sklopa ga posodobi.**
- `docs/ARCHITECTURE.md` — kje kaj je (vsi trije repozitoriji, produkcija, računi).

## Produkcija in kako pride koda vanjo

- Veja `main` = produkcija. Render ima vklopljen auto-deploy: **vsak merge v main je v ~60 s živ**
  (`npm run migrate && npm start`, migracije tečejo ob vsakem deployu).
- Zato: **nikoli ne potiskaj neposredno v main.** Delaj na veji, odpri PR, počakaj na zelen
  workflow `Testi`, šele nato merge. Zaščita veje to tudi vsiljuje.
- Backend: `https://outly-backend-roy3.onrender.com` · admin panel `/admin/` · Render storitev
  `srv-d5fuiovgi27c73e4boq0`, baza `outly-db` (`dpg-daf7vav40ujc73a28g8g-a`, Frankfurt).
- Po deployu preveri: `GET /clubs` in `GET /events` → 200, `GET /me/invites` brez žetona → 401.

## Struktura

```
index.js            ves API (en proces; poti, middleware requireAuth/requireRole/requireClub)
admin/index.html    admin panel (ena datoteka, brez ogrodja, prijava prek Supabase)
db/migrate.js       zaganjalnik migracij (evidenca schema_migrations, odtis datoteke, advisory lock)
db/migracije/       NNN_ime.sql — 000…015; VSAKA sprememba sheme je nova oštevilčena migracija
db/VSE_MIGRACIJE.sql združen izpis vseh migracij (blok brez BEGIN/COMMIT + sha256[:16] odtis)
db/schema.sql       izvoz sheme (pg_dump) po zadnji migraciji — mora slediti
_testi/             testne skripte (vsaka dvigne svoj JWKS + backend na svojem portu)
.env.example        vse okoljske spremenljivke z razlago; prave vrednosti so samo na Renderju
```

## Trda pravila

1. **Živa baza je dosegljiva SAMO prek migracij.** Nikoli ne sprejmi `DATABASE_URL` produkcije.
   Enkratni popravki podatkov = oštevilčena migracija. Vsebina (klubi, dogodki) gre prek API-ja, ne migracij.
2. Nova migracija → dopiši v `db/VSE_MIGRACIJE.sql` (z odtisom) in osveži `db/schema.sql`. Že uporabljene
   migracije se **ne spreminjajo** (migrate.js zavrne spremenjen odtis → deploy pade).
3. **Poverilnic ne sprejemaj in ne zapisuj**: ne gesel, ne API ključev, ne `DATABASE_URL`, ne žetonov.
   Za admin dejanja v produkciji uporabi servisni račun `agent@outly.si` (geslo ima Martin).
4. `SELECT *` na javnih poteh je prepovedan — stolpce naštevaj (`JAVNI_STOLPCI_KLUBA` ipd.);
   `stripe_account_id` in podobno ne sme uhajati.
5. Zneski so **celi centi v EUR**. Nikoli plavajoča vejica.
6. pg BIGINT pride kot niz — globalno rešeno s `setTypeParser(20)`; pri novih BIGINT stolpcih preveri.
7. JSONB polja pošiljaj kot `JSON.stringify(x)::jsonb` — pg bi JS seznam poslal kot Postgres ARRAY.
8. Resend SDK ob napaki NE vrže izjeme — vrne `{ error }`. Preveri.
9. Vloga (`user | business | admin`) in vloga v klubu (`owner | manager | doorman`) se uveljavljata
   **na strežniku** (`requireRole`, `requireClub`) ob vsakem klicu. Aplikacija le kaže drug obraz.
10. Omejevalnik poskusov je v pomnilniku procesa — testne skripte rabijo svež proces.

## Avtentikacija (Supabase Auth, od 11. 9. 2026)

Backend lastnih žetonov ne izdaja. Preveri Supabasov ES256 JWT prek JWKS
(`SUPABASE_URL/auth/v1/.well-known/jwks.json`, vgrajen `crypto`, brez odvisnosti). Poti `/auth/*` ni več.
`users.id` je INTEGER, `users.supabase_uid` UUID; vrstica nastane ob prvem klicu (povezava po e-naslovu
samo če `user_metadata.email_verified = true`). JWKS nedosegljiv → 503 (ne 401). `service_role` ključa
backend NE rabi in ga v okolju NE sme biti.

## Testiranje (obvezno pred PR-jem)

```bash
npm ci
# PostgreSQL 16 lokalno (ali docker: postgres:16), prazna baza:
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly
npm run migrate          # vse migracije na prazni bazi
npm test                 # _testi/*.js — vsaka skripta TRUNCATE-a tabele in dvigne svoj backend
```
Isto teče v GitHub Actions (`.github/workflows/testi.yml`) ob vsakem PR-ju. Nova funkcionalnost = nova
testna skripta v `_testi/` po vzorcu `test_vabila.js` (lokalni JWKS, ES256 podpis, svež port) in dodana v
`npm test`. Migracijo preveri na prazni bazi IN na bazi s podatki.

## Sporočila commitov

Slovenščina, brez šumnikov, prva vrstica kaj, nato odstavek »Preverjeno: …« (kateri testi, kaj ročno).

## Kaj odloči agent, kaj Martin

Agent sam: vse tehnično in povratno. Martin: karkoli stane denar, spreminja nastavitve računov
(Render, GitHub, Supabase, Resend, Cloudflare, Apple, Stripe), briše ali spreminja produkcijske podatke,
pravne odločitve. Če Martina ni na zvezi: izberi najbolj smiselno pot, zapiši predpostavko v STATE.md, delaj naprej.
