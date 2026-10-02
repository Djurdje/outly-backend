---
name: obnova-baze
description: Varnostna kopija produkcijske baze outly-db izven Renderja (dnevni izvoz, šifriran z age) in postopek obnove. Uporabi, ko je baza izgubljena ali pokvarjena, ko Martin dela mesečni preizkus kopije, ali ko se spreminja nastavitev kopij (ključ, secrets).
---

# Obnova baze `outly-db` iz varnostne kopije

Issue #88. **Obnova v PRODUKCIJO samo z Martinovim DA.** Agent nikoli ne sprejme in ne zapiše `DATABASE_URL`, gesel ali zasebnega ključa:
ukaze s temi vrednostmi poganja Martin v svojem terminalu, agent mu jih pripravi.

## Kako kopija nastane (da veš, kaj imaš)

- Workflow `Varnostna kopija baze` (`.github/workflows/kopija.yml`) teče vsak dan ob 06:23 UTC (08:23 poleti / 07:23 pozimi; GitHub cron zna zamuditi) in ročno. Job teče v GitHub environmentu `kopije`, ki je omejen na vejo `main`.
- Prek `GET /admin/api/export` (servisni admin račun, prijava s Supabase) potegne **logični izvoz vseh tabel** kot JSON — isti izvoz in ista obnova
  (`db/obnovi_izvoz.js`) kot v `ARCHITECTURE.md`, razdelek »Varnostne kopije in obnova«. **Ni `pg_dump`**: zunanji dostop do `outly-db` je
  zaprt (STATE.md, 30. 9. 2026), GitHubovi runnerji pa nimajo stalnega IP-ja; z API-jem baza ostane zaprta.
- Izvoz se stisne (gzip) in **šifrira z javnim ključem age**; v artefakt `outly-db-kopija-YYYY-MM-DD` gresta samo `outly-db-YYYY-MM-DD.json.gz.age`
  in `….sha256`. Hrani se 30 dni. Repo je javen, artefakt lahko prenese vsak prijavljen GitHub uporabnik — brez zasebnega ključa je neuporaben.
- **Isti zagon takoj preizkusi obnovo** (pred šifriranjem): migracije v `postgres:16` → `db/obnovi_izvoz.js` → neodvisna primerjava števil vrstic po
  tabelah in seznama migracij (`_orodja/kopija/stevila.js`). Preverba popolnosti: **vsaka tabela migrirane sheme mora biti v izvozu** (tudi z 0 vrsticami),
  sicer je zagon rdeč. Preverba padca: če število vrstic `users`, `orders` ali `tickets` pade za > 20 % glede na prejšnji zagon (števila so v `actions/cache`,
  ne v artefaktu), je zagon rdeč (kopija je vseeno shranjena); namerno čiščenje potrdiš z ročnim zagonom `potrdi_padec = true`.
  V javnem dnevniku in povzetku so samo imena tabel in OK/NAPAKA — števila uporabnikov/naročil so poslovna informacija.
- Ob napaki ali prekinitvi: rdeč zagon (mail) + push na ntfy (`NTFY_TOPIC`). Healthchecks (`HC_URL_KOPIJE`, obvezen del nastavitve) javi, če kopija sploh ne steče.
- Mesečno (`Preizkus kopije (mesecni)`, 1. v mesecu): preveri, da je shranjena kopija sveža (≤ 50 h), cela (sha256) in šifrirana, ter odpre issue-opomnik
  za Martinov ročni preizkus.

**Česa kopija NE vsebuje:** Supabase Auth (gesla/prijave so v Supabase; v bazi je samo `users.supabase_uid`) — zanj velja Supabaseov paket;
Cloudinary slike; Stripe; nastavitve Rendera. Časovni žigi so v izvozu zaokroženi na milisekundo (JS `Date`), kar ne vpliva na delovanje.

## Nastavitev (enkratno, Martin, ~25 min)

1. **Ključ age.** Z https://github.com/FiloSottile/age/releases prenesi age za Windows (`age.exe`, `age-keygen.exe`), nato v PowerShellu:
   `.\age-keygen.exe -o outly-kopija-kljuc.txt` — izpiše vrstico `Public key: age1…`.
   - **Datoteka `outly-kopija-kljuc.txt` je ZASEBNI ključ.** Shrani jo v upravljalnik gesel in še eno kopijo na USB/izpis. **Nikoli** v GitHub, mail, chat ali repo.
     Brez nje so vse kopije neberljive; kdor jo ima, bere vse osebne podatke.
   - Javni ključ (`age1…`) ni skrivnost. Neobvezno naredi drugi ključ (rezerva) in oba vpiši, ločena s presledkom.
2. **Poseben račun za kopije.** Ne uporabi `agent@outly.si` ali svojega računa. Backend za `GET /admin/api/export` zahteva vlogo **`admin`**
   (`admin.use(requireAuth, requireRole("admin"))` v `index.js` velja za vse poti pod `/admin/api`; vloge `business`/`user` dobijo 403). Najmanjša vloga, ki zadošča, je torej
   `admin` — račun lahko tudi vse ostalo v admin panelu, zato mu daj dolgo naključno geslo, ki ga pozna samo GitHub, in ga ne uporabljaj drugje.
   *Predlog (ni implementirano):* Issue »vloga `backup` samo za izvoz« (nova vrednost v `users_role_chk`, `requireRole("admin","backup")` samo na `/export`), da uhajanje gesla ne pomeni polne admin pravice.
   - Supabase → Authentication → Users → *Add user*: npr. `kopije@outly.si`, **Auto Confirm User** obkljukan (backend poveže račun po e-naslovu samo, če je `email_verified` true),
     naključno geslo 24+ znakov. CAPTCHA in obvezen MFA (AAL2) za ta račun ne smeta biti vklopljena — prijava z geslom iz workflowa bi padla.
   - Prvi zagon bo vrnil **403** (račun ob prvem klicu nastane v bazi z vlogo `user`). Nato: admin panel → Uporabniki → `kopije@outly.si` → vloga `admin`, in zagon ponovi.
3. **GitHub environment `kopije` (varovalo pred uhajanjem gesla z veje).** Repo → Settings → Environments → *New environment* → ime `kopije`.
   V *Deployment branches and tags* izberi *Selected branches and tags* in dodaj samo `main`. **Secrets/variables vpiši TAM, ne na ravni repozitorija:**
   - *Environment variables*: `BACKUP_AGE_PUBLIC_KEYS` = javni ključ(i) `age1…`;
   - *Environment secrets*: `BACKUP_ADMIN_EMAIL` (`kopije@outly.si`), `BACKUP_ADMIN_PASSWORD`, `HC_URL_KOPIJE` (korak 4).
   Brez tega bi vsak zagon z druge veje (ročni zagon iz veje, spremenjen workflow) dobil geslo; z njim pade že pri »Branch not allowed«.
   `NTFY_TOPIC` ostane repo-level secret (že obstaja).
4. **Healthchecks.io (obvezno):** nov check »Outly kopija«, **Period 1 day, Grace 24 hours**, obvestilo na isti ntfy kanal; njegov ping URL → environment secret `HC_URL_KOPIJE`.
   Brez njega kopija, ki sploh ne steče (cron izpade, workflow onemogočen), ostane neopažena; zagon brez secreta izpiše opozorilo.
5. **Prvi zagon:** Actions → *Varnostna kopija baze* → *Run workflow* (veja `main`). Zelen zagon = v *Artifacts* je kopija, v povzetku OK/NAPAKA po tabelah.
   Za preizkus alarma isti workflow z `test` = `true` (pošlje samo testni push).
6. **Isti dan dešifriraj prvo kopijo** (ne čakaj na mesečni opomnik): prenesi artefakt, nato v mapi z datotekami
   `.\age.exe -d -i outly-kopija-kljuc.txt -o izvoz.json.gz outly-db-YYYY-MM-DD.json.gz.age` in
   `node -e "require('fs').writeFileSync('izvoz.json', require('zlib').gunzipSync(require('fs').readFileSync('izvoz.json.gz')))"`, nato
   `node _orodja/kopija/stevila.js povzetek izvoz.json` (v kloniranem repozitoriju) mora pisati »Izvoz je cel«. Datoteke nato izbriši. Če ne gre, popravi takoj, ne čez mesec.
7. Zunanjega dostopa do baze **ne odpiraj** (Render → Inbound IP Rules ostanejo prazna); kopija ga ne rabi.

## Prenos in dešifriranje (Martin, Windows/PowerShell; enako na Linuxu)

1. GitHub → repo → *Actions* → *Varnostna kopija baze* → izberi zagon (datum) → spodaj *Artifacts* → prenesi `outly-db-kopija-…` (zip) in ga razpakiraj.
   (Z `gh`: `gh run download <RUN_ID> -R Djurdje/outly-backend -n outly-db-kopija-YYYY-MM-DD`.)
2. Preveri celovitost: `Get-FileHash .\outly-db-YYYY-MM-DD.json.gz.age -Algorithm SHA256` mora dati isti odtis kot v `….sha256`
   (Linux: `sha256sum -c *.sha256`).
3. Dešifriraj: `.\age.exe -d -i outly-kopija-kljuc.txt -o izvoz.json.gz outly-db-YYYY-MM-DD.json.gz.age`
4. Razpakiraj (deluje povsod, kjer je Node): `node -e "require('fs').writeFileSync('izvoz.json', require('zlib').gunzipSync(require('fs').readFileSync('izvoz.json.gz')))"`
5. Hiter pregled: `node _orodja/kopija/stevila.js povzetek izvoz.json` (iz korena klona repozitorija) — izpiše čas izvoza, tabele in števila vrstic;
   izvoz je cel, če piše »Izvoz je cel«.
6. **Izvoz vsebuje osebne podatke in odtise gesel.** Hrani ga samo zasebno (`outly/backup/YYYY-MM-DD/` na Martinovem računalniku), nikoli v git. Po preizkusu izbriši `izvoz.json` in `izvoz.json.gz`.

## Obnova v novo bazo

Pogoj: klon repozitorija na commitu, katerega migracije ustrezajo izvozu (običajno trenutni `main`; če `db/obnovi_izvoz.js` javi, da se seznam migracij ne ujema,
vzemi commit iz dneva izvoza), `npm ci`, PostgreSQL **16**.

1. **Nova prazna baza.** Lokalno (`postgres://postgres:…@localhost:5432/outly_obnova`, v URL-ju mora pisati `localhost`) ali nova Render baza (**stane denar → Martinov DA**).
   Nikoli obstoječa produkcijska: skripta take zavrne.
2. `DATABASE_URL=<nova baza>` → `npm run migrate` (shema + servisni račun iz migracije 007).
3. `DELETE FROM users WHERE email='agent@outly.si';` (edini seed migracij; izvoz ga že vsebuje — past v STATE.md). Lokalno to naredi tudi
   `node _orodja/kopija/stevila.js pocisti-seed`.
4. `node db/obnovi_izvoz.js izvoz.json` (za cilj, ki ni `localhost`: dodaj `--cilj-ni-localhost`). Pričakovano: število vrstic po tabelah in »Obnova končana«.
   Napaka sredi poti = ROLLBACK, cilj ostane prazen.
5. Neodvisna primerjava: `node _orodja/kopija/stevila.js primerjaj izvoz.json` (cilj mora biti `localhost`) → »vse tabele se ujemajo«.
6. Zaženi backend na novi bazi (lokalno `npm start` z `DATABASE_URL`) in preveri `GET /clubs`, `GET /events` → 200, `GET /me/invites` brez žetona → 401.

## Obnova v produkcijo (samo z Martinovim DA)

Najprej preveri, ali ne zadošča **Renderjeva obnova na točko v času** (zadnji 3 dnevi, delovni prostor Hobby): ta ustvari novo instanco, brez te kopije.
Kopijo uporabi, ko je napaka starejša od 3 dni, ko je izgubljen Render račun ali ko je pokvarjena baza in Renderjeva obnova ni mogoča.

1. Povej Martinu, kaj bo stalo (nova Render baza ≈ 6 $/mesec za `0.1c-256mb`, na koncu staro pobrisati) in kaj se izgubi (spodaj). Počakaj na DA.
2. Martin ustvari novo bazo v Frankfurtu (PostgreSQL 16) in v njenih *Inbound IP Rules* **začasno** doda svoj IP (STATE.md: sicer External URL ne dela).
3. Koraki 2–5 iz razdelka »Obnova v novo bazo« z External URL nove baze, v Martinovem terminalu (z `--cilj-ni-localhost`).
4. Render → `outly-backend` → Environment → `DATABASE_URL` = **Internal** URL nove baze (to je sprememba nastavitev na Renderju: DA). Deploy.
5. Preveri produkcijo: `GET /clubs`, `GET /events` → 200, `GET /me/invites` brez žetona → 401, `outly.si` → 200; workflow `Nadzor produkcije` zelen.
6. Odstrani Martinov IP iz Inbound IP Rules. Staro bazo pobriši šele, ko je jasno, da je ne rabimo (DA).
7. Dopiši vrstico v `docs/INCIDENTI.md`; v `STATE.md` novo ime/ID baze.

**Kaj se izgubi ali zapleta po obnovi iz kopije:**
- Vse po času izvoza (do 24 h): naročila, vstopnice, registracije. Stripe plačila v tem oknu preveri v Stripe nadzorni plošči.
- Obnova **oživi vstopnice, ki so bile skenirane po izvozu** — pred dogodkom naredi svež izvoz ali ročno zaženi workflow tik pred obnovo, če je baza še brana.
- Supabase uporabniki niso v kopiji; `users.supabase_uid` se obnovi, prijava deluje, če je Supabase projekt isti.

## Mesečni preizkus (Martin, lokalno)

Sproži ga issue »Mesecni preizkus obnove kopije baze (YYYY-MM)« z oznako `martin`. Zakaj lokalno: zasebnega ključa **namenoma ni v GitHubu** — kdor lahko bere
GitHub secrets, bi bral tudi vse kopije in šifriranje ne bi imelo smisla. Samodejni del (dnevni preizkus obnove pred šifriranjem + mesečni pregled celovitosti) dokazuje,
da je izvoz obnovljiv in da je shranjena datoteka cela; **Martinov del dokazuje, da ključ res odpre kopijo.**

- **Hitri preizkus (~5 min, vsak mesec):** koraki »Prenos in dešifriranje« 1–5 z najnovejšo kopijo, nato izbriši `izvoz.json*`. Zapri issue.
- **Polni preizkus (vsake 3 mesece ali po večji spremembi sheme, ~15 min):** še »Obnova v novo bazo« na lokalni PostgreSQL 16 (ali Docker `postgres:16`). Ob napaki vrstica v `docs/INCIDENTI.md`.

## Menjava ključa

Nov `age-keygen` → v `BACKUP_AGE_PUBLIC_KEYS` dodaj novi javni ključ (stari ostane, dokler obstajajo kopije zanj, 30 dni) → po 30 dneh odstrani starega.
Starih kopij ne da šifrirati znova; stari zasebni ključ hrani, dokler te kopije ne potečejo. Ob sumu, da je zasebni ključ ušel: nov ključ takoj in
razmisli, ali so artefakti (javni za prijavljene) že bili preneseni — prisilno jih izbriši v Actions → artefakti.

## Če dnevna kopija pade

| Znak v dnevniku | Pomen | Ukrep |
|---|---|---|
| `Branch not allowed` / job se ne zažene | zagon ne z veje `main` (environment `kopije`) | zaženi z `main` |
| `Manjka nastavitve v environmentu kopije: …` | secret/variable ni vpisan v environment | Nastavitev, korak 3 |
| `Prijava … ni uspela (HTTP 400)` | napačen e-naslov/geslo ali uporabnika ni v Supabase | preveri secrets v environmentu, Supabase → Users |
| `Izvoz ni uspel … HTTP 403` | (a) račun ni `admin` v bazi (prvi zagon vedno!) ali (b) `Email not verified`: e-naslov v Supabase ni potrjen (`email_verified`), backend ga brez tega ne poveže | (a) admin panel → Uporabniki → vloga `admin`; (b) Supabase → Users → potrdi e-naslov / Auto Confirm |
| `Prijava … HTTP 400` s captcha/MFA | CAPTCHA ali obvezen MFA na Supabase | za ta račun izklopi; prijava z geslom iz workflowa ne more rešiti izziva |
| `Izvoz ni uspel … HTTP 401` | žeton zavrnjen (JWKS/Supabase) | preveri nadzor produkcije, ponovi |
| `Izvoz ni uspel … 5xx` / koda 18, 56 | backend ali baza izpadla, deploy v teku | ponovi zagon; če se ponovi, INCIDENTI + `Nadzor produkcije` |
| `BACKUP_AGE_PUBLIC_KEYS vsebuje nekaj, kar ni javni ključ` | vnesen napačen niz (zasebni ključ?) | takoj izbriši variable, če je bil vnesen zasebni ključ; vnesi `age1…` |
| `Seznam migracij v cilju se ne ujema z izvozom` | main ima novejšo migracijo, ki je produkcija še nima (deploy v teku/padel) | počakaj na deploy in ponovi; kopija je bila vseeno shranjena |
| `Preverba … tabela migrirane sheme MANJKA v izvozu` | izvoz ne vsebuje vse tabele (napaka izvoza ali ročno spremenjen izvoz) | kopija ni popolna: ponovi zagon, če se ponovi, INCIDENTI + preglej `GET /admin/api/export` |
| `Sumljiv padec … users/orders/tickets` | število vrstic je padlo za > 20 % glede na prejšnji zagon | preveri, ali je bilo brisanje namerno; če je, zaženi ročno s `potrdi_padec = true` |
| `Obnova izvoza je padla` + »podrobnosti skrite« | nepričakovana napaka (lahko vsebuje vrednosti) | prenesi kopijo in obnovi lokalno po tem skillu |

Tri zaporedne rdeče kopije = sum na resnično napako, ne na naključje: zapiši v `docs/INCIDENTI.md`.
