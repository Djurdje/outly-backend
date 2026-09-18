# Outly backend — navodila za agente

Express + PostgreSQL 16 na Renderju. Streže iOS aplikacijo Outly in admin panel.
Odgovarjaj v slovenščini, kratko in naravnost. Martin (lastnik) ni razvijalec po
poklicu: razlagaj posledice, ne implementacijskih podrobnosti. Če se moti, povej.

Skupni možgani projekta (preberi, preden karkoli spremeniš):
- `docs/DECISIONS.md` — odločitve, ki so padle. Ne odpiraj jih znova. Pomembne imajo polja *vir/dokaz*, *velja dokler*, *nadomeščena z*.
- `docs/STATE.md` — pasti, predpostavke in kar ni razvidno drugje. **Ob koncu vsakega sklopa ga posodobi.**
- `docs/ARCHITECTURE.md` — kje kaj je + razdelek **»Poslovne invariante«** (kaj se ne sme zgoditi, kaj to preprečuje, kateri test to lovi).
- `docs/INCIDENTI.md` — kaj je že pokvarilo produkcijo. **Preberi pred diagnozo, dopiši ob koncu seje.**
- **Odprte naloge so v GitHub Issues** (oznaka `agent` = agent, `martin` = Martin), ne v STATE.md.

## Produkcija in kako pride koda vanjo

- Veja `main` = produkcija. Render ima vklopljen auto-deploy: **vsak merge v main je v ~60 s živ**
  (`npm run migrate && npm start`, migracije tečejo ob vsakem deployu).
- Zato: **nikoli ne potiskaj neposredno v main.** Delaj na veji, odpri PR, počakaj na zelen workflow `Testi`
  in **PR sam mergaj** (PR mergaj s squash (GitHub MCP orodje merge_pull_request; gh CLI v oblaku ni) in pobrisi vejo, ali `--auto`, da se merge zgodi ob zelenem CI). Zaščita veje
  vsiljuje PR + zelen CI; človeka vmes ni – od Martinovega ukaza do produkcije gre samodejno (odločeno 16. 9. 2026).
- **Po merge-u počakaj na deploy (~60–90 s) in preveri produkcijo** (spodaj). Če pade, takoj odpri popravek ali revert PR.
- Edina izjema, kjer NE mergaš brez Martinovega DA: migracija, ki briše ali spreminja obstoječe produkcijske podatke
  (DROP, DELETE, UPDATE na podatkih, sprememba tipa stolpca s podatki). Tako migracijo pripravi, testiraj, odpri PR in počakaj.
- **Oznaka `odobril-martin`** (workflow `Zascita`, `.github/workflows/zascita.yml`): PR, ki spreminja
  `.github/workflows/**`, `CLAUDE.md`, `.claude/**`, `db/migracije/**` ali plačilno/dostopno logiko
  (`requireRole`, `requireClub`, `orders`, `tickets`, `stripe` v `.js`/`.sql`), **pade brez te oznake**.
  Oznako doda **Martin**; agent si je ne sme dodati sam — s tem bi izklopil lastni alarm. Če je PR rdeč zaradi tega,
  ni kaj popravljati: povej Martinu, kaj v PR-ju je občutljivo, in počakaj.
  (Workflow teče kot `pull_request_target`, torej se vedno izvede različica z `main` — PR te preverbe ne more izklopiti.)
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
docs/               skupni mozgani: DECISIONS, STATE, ARCHITECTURE (+ invariante), INCIDENTI
.github/workflows/  Testi (PR + main), Nadzor produkcije (vsakih 15 min + Healthchecks ping), Zascita (oznaka odobril-martin)
.github/pull_request_template.md   kontrolni seznam pred merge-om
.env.example        vse okoljske spremenljivke z razlago; prave vrednosti so samo na Renderju
```

## Trda pravila

Pravila, ki jih danes drži test (I1–I10 v `docs/ARCHITECTURE.md`, razdelek »Poslovne invariante«), so tu samo
kot sklic — merodajen je test, ne ta seznam. Če spreminjaš kaj, kar se dotakne invariante, najprej preberi njeno vrstico.

1. **Živa baza je dosegljiva SAMO prek migracij.** Nikoli ne sprejmi `DATABASE_URL` produkcije.
   Enkratni popravki podatkov = oštevilčena migracija. Vsebina (klubi, dogodki) gre prek API-ja, ne migracij.
2. Nova migracija → dopiši v `db/VSE_MIGRACIJE.sql` (z odtisom) in osveži `db/schema.sql`. Že uporabljene
   migracije se **ne spreminjajo** (migrate.js zavrne spremenjen odtis → deploy pade).
3. **Poverilnic ne sprejemaj in ne zapisuj**: ne gesel, ne API ključev, ne `DATABASE_URL`, ne žetonov.
   Za admin dejanja v produkciji uporabi servisni račun `agent@outly.si` (geslo ima Martin).
4. `SELECT *` na javnih poteh je prepovedan — stolpce naštevaj (`JAVNI_STOLPCI_KLUBA` ipd.). Invarianta **I4**.
5. Zneski so **celi centi v EUR**, nikoli plavajoča vejica. Invarianta **I9**.
6. pg BIGINT pride kot niz — globalno rešeno s `setTypeParser(20)`; pri novih BIGINT stolpcih preveri.
7. JSONB polja pošiljaj kot `JSON.stringify(x)::jsonb` — pg bi JS seznam poslal kot Postgres ARRAY.
8. Resend SDK ob napaki NE vrže izjeme — vrne `{ error }`. Preveri.
9. Vloge se uveljavljajo **na strežniku** ob vsakem klicu, ne v aplikaciji. Invarianta **I5**.
10. Omejevalnik poskusov je v pomnilniku procesa — testne skripte rabijo svež proces.

## Avtentikacija (Supabase Auth, od 11. 9. 2026)

Backend lastnih žetonov ne izdaja. Preveri Supabasov ES256 JWT prek JWKS
(`SUPABASE_URL/auth/v1/.well-known/jwks.json`, vgrajen `crypto`, brez odvisnosti). Poti `/auth/*` ni več.
`users.id` je INTEGER, `users.supabase_uid` UUID; vrstica nastane ob prvem klicu (povezava po e-naslovu
samo če `user_metadata.email_verified = true`). JWKS nedosegljiv → **503, ne 401** (invarianta **I10**: izpad
Supabase ne sme odjaviti uporabnikov). `service_role` ključa backend NE rabi in ga v okolju NE sme biti.

## Testiranje (obvezno pred PR-jem)

```bash
npm ci
# PostgreSQL 16 lokalno (ali docker: postgres:16), prazna baza:
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly
npm run migrate          # vse migracije na prazni bazi
npm test                 # _testi/*.js — vsaka skripta TRUNCATE-a tabele in dvigne svoj backend
```
V URL-ju mora pisati **`localhost`**, ne `127.0.0.1`: SSL se izklopi samo po tem nizu, sicer migracije padejo
z »The server does not support SSL connections«.

Isto teče v GitHub Actions (`.github/workflows/testi.yml`) ob vsakem PR-ju. Nova funkcionalnost = nova
testna skripta v `_testi/` po vzorcu `test_vabila.js` (lokalni JWKS, ES256 podpis, svež port) in dodana v
`npm test`. Migracijo preveri na prazni bazi IN na bazi s podatki.

**Popravek hrošča brez regresijskega testa ni popravek.** Test napiši prvi, poženi ga na stari kodi (mora pasti),
šele nato popravi. Nova invarianta gre v `docs/ARCHITECTURE.md` skupaj z mehanizmom in testom.

## Incidenti

`docs/INCIDENTI.md` je dnevnik vsega, kar je v produkciji odpovedalo ali sprožilo alarm — **tudi lažne alarme**.

- **Preberi ga, preden postaviš diagnozo.** Odgovor je pogosto že tam in prihrani napačno smer.
- **Dopiši vrstico ob koncu vsake seje, ki se je dotaknila produkcije**, tudi če vzroka nisi našel
  (»vzrok neznan« je podatek; tri take vrstice zapored so sum na resnično napako).
- Velja posebej za rutino **Popravljalec**: alarm → preberi INCIDENTI → popravi ali ugotovi, da je lažen → dopiši vrstico.
- Iz incidenta pogosto pade past (`STATE.md`) ali odločitev (`DECISIONS.md`) — v INCIDENTI ostane samo dogodek.

## Skilli (`.claude/skills/`)

Skill je zapisan postopek, ki ga agent sicer vsakič znova odkriva. **Pravilo: ko si moral nekaj odkrivati
drugič, to zapiši kot skill** — prvič je delo, drugič je vzorec.

- Ena mapa na skill: `.claude/skills/<ime>/SKILL.md`, v njej kratek opis, kdaj se uporabi, in koraki.
- Kandidati: postavitev lokalnega PostgreSQL-a za teste, preverjanje produkcije po deployu, priprava nove migracije,
  headless preverjanje strani, branje Figme brez MCP kvote.
- Skill je postopek, ne odločitev in ne past. Odločitev gre v `DECISIONS.md`, past v `STATE.md`, incident v `INCIDENTI.md`.
- Skilli in `CLAUDE.md` so pod zaščito `odobril-martin` (pot `.claude/**`) — spremembe gredo skozi Martina.

## Spremembe API-ja so samo dodajanje

Backend streže iOS aplikacijo, ki je pri uporabnikih **na telefonih** in se ne posodobi takrat, ko se posodobi backend
(TestFlight build, Apple pregled, uporabnik mora namestiti). Zato:

- **Dodajanje polja ali poti je prosto.** Nova polja v odgovorih star odjemalec preprosto spregleda.
- **Brisanje ali preimenovanje polja podre aplikacijo v rokah uporabnika.** Če je res nujno:
  1. zapiši v `docs/STATE.md` (kaj, od kdaj, kaj pade),
  2. **obvesti agenta iOS in agenta spletne strani** — v opisu PR-ja, z imenom polja in nadomestilom,
  3. staro polje pusti živeti vsaj en TestFlight cikel, šele nato ga odstrani.
- Isto velja za spremembo tipa ali pomena polja (npr. iz števila v niz) — to je brisanje z drugim imenom.
- Na drugi strani: nova polja v iOS modelih vedno s privzeto vrednostjo, da star backend ne podre dekodiranja.

## Za agente drugih dveh repozitorijev (iOS, spletna stran)

Skupni dokumenti živijo **samo tu**, v `Djurdje/outly-backend` (repo je javen, žeton ni potreben):

```
https://raw.githubusercontent.com/Djurdje/outly-backend/main/docs/DECISIONS.md
https://raw.githubusercontent.com/Djurdje/outly-backend/main/docs/STATE.md
https://raw.githubusercontent.com/Djurdje/outly-backend/main/docs/ARCHITECTURE.md
https://raw.githubusercontent.com/Djurdje/outly-backend/main/docs/INCIDENTI.md
```

Preden se lotiš česarkoli, kar se dotika API-ja, vlog, plačil ali računov, jih **preberi** in
**v `STATE.md` oziroma v opis PR-ja zapiši commit, ki si ga bral** (`git ls-remote https://github.com/Djurdje/outly-backend main`
ali SHA iz glave datoteke na GitHubu). Brez tega se ne da ugotoviti, ali si delal po starih odločitvah.
Odprte naloge so v **GitHub Issues** repozitorija `outly-backend`, ne v teh datotekah.

## Sporočila commitov

Slovenščina, brez šumnikov, prva vrstica kaj, nato odstavek »Preverjeno: …« (kateri testi, kaj ročno).

## Kaj odloči agent, kaj Martin

Agent sam: vse tehnično in povratno. Martin: karkoli stane denar, spreminja nastavitve računov
(Render, GitHub, Supabase, Resend, Cloudflare, Apple, Stripe), briše ali spreminja produkcijske podatke,
pravne odločitve. Če Martina ni na zvezi: izberi najbolj smiselno pot, zapiši predpostavko v STATE.md, delaj naprej.
